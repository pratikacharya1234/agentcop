//! Script inspection (C2-R3). When a Bash command runs a script file, the file's contents are
//! judged with the same rules as a Bash command.
//!
//! PLAN:
//! 1. Resolve the file path (cwd, `~`, symlinks), the same way the session state does.
//! 2. A script the agent wrote or changed this session asks. Its contents are still judged.
//! 3. A missing, unreadable, binary, non-UTF-8 or over-256 KB script asks. A `script-maybe` path
//!    (a path that may be a binary) is skipped unless it starts with `#!`.
//! 4. The text is parsed with cop-shell. Unparseable text is denied (fail closed).
//! 5. Its lines get the Bash rules and its honeytokens. Scripts it runs are inspected too, up to
//!    MAX_SCRIPT_DEPTH levels; deeper asks.
//! 6. The strictest verdict wins, and each reason names the file and line.

use crate::{keep_stricter, Judge};
use cop_core::Verdict;
use std::fs::{self, File};
use std::io::Read;
use std::path::Path;

pub const MAX_SCRIPT_BYTES: u64 = 256 * 1024;
pub const MAX_SCRIPT_DEPTH: usize = 3;

/// The script files a list of action lines runs: (action index, path, may be a binary).
pub(crate) fn script_calls(actions: &[String]) -> Vec<(usize, &str, bool)> {
    actions
        .iter()
        .enumerate()
        .filter_map(|(i, a)| {
            a.strip_prefix("script ")
                .map(|p| (i, p, false))
                .or_else(|| a.strip_prefix("script-maybe ").map(|p| (i, p, true)))
        })
        .collect()
}

impl Judge {
    /// Judge one script file. `None` means "not a script" (only for a `maybe` path).
    pub(crate) fn inspect_script(
        &self,
        raw: &str,
        maybe: bool,
        depth: usize,
        written: &[String],
    ) -> Option<(Verdict, String)> {
        if depth > MAX_SCRIPT_DEPTH {
            let why = format!("{raw}: scripts nested deeper than {MAX_SCRIPT_DEPTH} levels; asks");
            return Some((Verdict::Ask, why));
        }
        let cwd = std::env::current_dir().unwrap_or_default();
        let abs = cop_core::absolute_path(raw, &cwd);
        let text = match read_script(Path::new(&abs), maybe) {
            Ok(None) => return None,
            Ok(Some(text)) => text,
            Err(why) => return Some((Verdict::Ask, format!("{raw}: {why}"))),
        };
        let analysis = cop_shell::analyze(&text);
        if analysis.unparsed {
            let why = format!("{raw}: could not read the script; denied (fail closed)");
            return Some((Verdict::Deny, why));
        }
        let mut result = (Verdict::Allow, "No rules matched".to_string());
        if written.contains(&abs) {
            let why = format!("{raw}: created or changed by the agent this session; asks");
            result = keep_stricter(result, (Verdict::Ask, why));
        }
        if let Some(reason) = self.honeytoken_reason(&text) {
            result = keep_stricter(result, (Verdict::Deny, format!("{raw}: {reason}")));
        }
        if let Some(hit) =
            self.match_rules("Bash", &analysis.actions, &analysis.lines, Some(raw), &text)
        {
            result = keep_stricter(result, hit);
        }
        for (i, child, child_maybe) in script_calls(&analysis.actions) {
            if let Some((verdict, reason)) =
                self.inspect_script(child, child_maybe, depth + 1, written)
            {
                let line = analysis.lines[i];
                result = keep_stricter(result, (verdict, format!("{raw} line {line} -> {reason}")));
            }
        }
        Some(result)
    }
}

/// Read a script. Ok(None) only for a `maybe` path that is not a shell script.
fn read_script(path: &Path, maybe: bool) -> Result<Option<String>, &'static str> {
    let meta = match fs::metadata(path) {
        Ok(meta) if meta.is_file() => meta,
        _ if maybe => return Ok(None),
        _ => return Err("is missing or not a regular file; asks"),
    };
    if maybe && !starts_with_shebang(path) {
        return Ok(None);
    }
    if meta.len() > MAX_SCRIPT_BYTES {
        return Err("is over 256 KB; asks");
    }
    let bytes = fs::read(path).map_err(|_| "could not be read; asks")?;
    if bytes.contains(&0) {
        return Err("is a binary file; asks");
    }
    String::from_utf8(bytes)
        .map(Some)
        .map_err(|_| "is not UTF-8 text; asks")
}

fn starts_with_shebang(path: &Path) -> bool {
    let mut head = [0u8; 2];
    File::open(path)
        .and_then(|mut f| f.read_exact(&mut head))
        .is_ok()
        && &head == b"#!"
}
