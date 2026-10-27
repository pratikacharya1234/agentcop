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

use crate::{keep_stricter, Judge, SessionView};
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

/// The files a list of action lines runs with a runner (python, make, npm run...), with the action index.
pub(crate) fn runs_file_calls(actions: &[String]) -> Vec<(usize, &str)> {
    actions
        .iter()
        .enumerate()
        .filter_map(|(i, a)| a.strip_prefix("runs-file ").map(|p| (i, p)))
        .collect()
}

impl Judge {
    /// A file a runner executes. Its contents are not read (they are not shell). The judge asks when
    /// the agent wrote or changed it this session.
    pub(crate) fn runs_file_verdict(
        &self,
        raw: &str,
        cwd: &Path,
        written: &[String],
    ) -> Option<(Verdict, String)> {
        let abs = cop_core::absolute_path(raw, cwd);
        written.contains(&abs).then(|| {
            (
                Verdict::Ask,
                format!("{raw}: created or changed by the agent this session; asks"),
            )
        })
    }

    /// Judge one script file. `None` means "not a script" (only for a `maybe` path).
    /// Relative paths resolve against `cwd`, the directory of the event.
    pub(crate) fn inspect_script(
        &self,
        raw: &str,
        maybe: bool,
        depth: usize,
        session: SessionView<'_>,
        cwd: &Path,
    ) -> Option<(Verdict, String)> {
        if depth > MAX_SCRIPT_DEPTH {
            let why = format!("{raw}: scripts nested deeper than {MAX_SCRIPT_DEPTH} levels; asks");
            return Some((Verdict::Ask, why));
        }
        let abs = cop_core::absolute_path(raw, cwd);
        // FP-1: an unchanged, tracked script runs as it would with no secret read. Only the "after a secret read"
        // asks are dropped. Its denies and its other asks still apply.
        let session = if unchanged_since_session_start(&abs, &session) {
            SessionView {
                sensitive: false,
                ..session
            }
        } else {
            session
        };
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
        if session.written.contains(&abs) {
            let why = format!("{raw}: created or changed by the agent this session; asks");
            result = keep_stricter(result, (Verdict::Ask, why));
        }
        if let Some(reason) = self.honeytoken_reason(&text) {
            result = keep_stricter(result, (Verdict::Deny, format!("{raw}: {reason}")));
        }
        if let Some(hit) = self.match_rules(
            "Bash",
            &analysis.actions,
            &analysis.lines,
            Some(raw),
            &text,
            session.sensitive,
        ) {
            result = keep_stricter(result, hit);
        }
        for (i, child, child_maybe) in script_calls(&analysis.actions) {
            if let Some((verdict, reason)) =
                self.inspect_script(child, child_maybe, depth + 1, session, cwd)
            {
                let line = analysis.lines[i];
                result = keep_stricter(result, (verdict, format!("{raw} line {line} -> {reason}")));
            }
        }
        Some(result)
    }
}

/// FP-1 trust rule. A script is unchanged when all of these hold: it is tracked in git, it matches HEAD, the agent
/// did not write it this session, and its mtime is before the session's SessionStart heartbeat. Anything else
/// (untracked, modified, no heartbeat for the session) is not trusted.
pub(crate) fn unchanged_since_session_start(abs: &str, session: &SessionView<'_>) -> bool {
    let Some(started) = session.started else {
        return false;
    };
    if session.written.iter().any(|w| w == abs) {
        return false;
    }
    let path = Path::new(abs);
    let (Some(dir), Some(name)) = (path.parent(), path.file_name()) else {
        return false;
    };
    let mtime = fs::metadata(path)
        .and_then(|m| m.modified())
        .ok()
        .and_then(|t| t.duration_since(std::time::UNIX_EPOCH).ok())
        .map(|d| d.as_secs());
    if !mtime.is_some_and(|m| m < started) {
        return false;
    }
    git_ok(dir, &["ls-files", "--error-unmatch", "--"], name)
        && git_ok(dir, &["diff", "--quiet", "HEAD", "--"], name)
}

/// True when `git <args> <name>` run in `dir` exits 0. A missing git or no repo is false (not trusted).
fn git_ok(dir: &Path, args: &[&str], name: &std::ffi::OsStr) -> bool {
    std::process::Command::new("git")
        .arg("-C")
        .arg(dir)
        .args(args)
        .arg(name)
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .status()
        .is_ok_and(|status| status.success())
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
