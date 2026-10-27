//! `agentcop doctor` and `agentcop policy check` (2026-10-27).
//!
//! PLAN:
//! 1. One line per check: PASS, WARN or FAIL. Every FAIL and WARN names the command that fixes it.
//! 2. Checks: modes of the state folder and its files; the hook path in settings.json (PreToolUse and
//!    SessionStart); the installed hook's version and identity against this CLI; the policy canaries; the
//!    evidence chain and its anchor; the last session heartbeat; the policy mode; raw-data archives on disk.
//! 3. The exit code is 1 when any check fails. Nothing is changed.
//! 4. `policy check FILE` runs the canaries against one policy file and exits 1 if any is allowed.

use cop_evidence::{final_hash, latest_archive, EvidenceStore};
use serde_json::Value;
use std::collections::BTreeSet;
use std::fs;
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::process::Command;

#[derive(Default)]
struct Tally {
    pass: usize,
    warn: usize,
    fail: usize,
}

fn line(tally: &mut Tally, status: &str, text: &str, fix: Option<&str>) {
    match status {
        "PASS" => tally.pass += 1,
        "WARN" => tally.warn += 1,
        _ => tally.fail += 1,
    }
    println!("{status}  {text}");
    if let Some(fix) = fix {
        println!("      fix: {fix}");
    }
}

fn mode_of(path: &Path) -> Option<u32> {
    fs::metadata(path)
        .ok()
        .map(|m| m.permissions().mode() & 0o777)
}

pub fn run() -> Result<(), String> {
    let home = dirs::home_dir().ok_or("Failed to find home directory")?;
    let state = home.join(".agentcop");
    let bin = state.join("bin").join("cop-hook");
    let mut t = Tally::default();
    println!("agentcop doctor (CLI {})", env!("CARGO_PKG_VERSION"));

    check_modes(&state, &mut t);
    check_settings(&home, &bin, &mut t);
    check_binary(&bin, &mut t);
    check_canaries_installed(&state, &mut t);
    check_chain(&state, &mut t);
    check_heartbeat(&state, &mut t);
    check_mode(&state, &mut t);
    check_archives(&state, &mut t);

    println!(
        "Summary: {} pass, {} warn, {} fail.",
        t.pass, t.warn, t.fail
    );
    if t.fail > 0 {
        std::process::exit(1);
    }
    Ok(())
}

fn check_modes(state: &Path, t: &mut Tally) {
    let mut bad: BTreeSet<String> = BTreeSet::new();
    let mut fixes: Vec<String> = Vec::new();
    if !state.exists() {
        line(
            t,
            "FAIL",
            "state folder ~/.agentcop does not exist",
            Some("agentcop install"),
        );
        return;
    }
    if mode_of(state) != Some(0o700) {
        bad.insert(format!(
            "{} is {:o}, want 700",
            state.display(),
            mode_of(state).unwrap_or(0)
        ));
        fixes.push(format!("chmod 700 {}", state.display()));
    }
    for entry in fs::read_dir(state).into_iter().flatten().flatten() {
        let path = entry.path();
        if path.is_file() {
            let want = if path.ends_with("bin/cop-hook") {
                0o700
            } else {
                0o600
            };
            if mode_of(&path) != Some(want) {
                bad.insert(format!(
                    "{} is {:o}, want {:o}",
                    path.display(),
                    mode_of(&path).unwrap_or(0),
                    want
                ));
                fixes.push(format!("chmod {:o} {}", want, path.display()));
            }
        }
    }
    if bad.is_empty() {
        line(
            t,
            "PASS",
            "folder and file modes: ~/.agentcop 0700, files 0600",
            None,
        );
    } else {
        let detail = bad.into_iter().collect::<Vec<_>>().join("; ");
        line(
            t,
            "FAIL",
            &format!("modes: {detail}"),
            Some(&fixes.join(" && ")),
        );
    }
}

fn check_settings(home: &Path, bin: &Path, t: &mut Tally) {
    let Ok(path) = crate::install::settings_path(home) else {
        line(
            t,
            "FAIL",
            "settings.json not found",
            Some("install Claude Code, then run agentcop install"),
        );
        return;
    };
    let text = fs::read_to_string(&path).unwrap_or_default();
    let settings: Value = serde_json::from_str(&text).unwrap_or(Value::Null);
    let bin_text = bin.to_string_lossy().into_owned();
    let mut missing = Vec::new();
    let mut wrong = Vec::new();
    for event in ["PreToolUse", "SessionStart"] {
        let commands: Vec<String> = settings["hooks"][event]
            .as_array()
            .into_iter()
            .flatten()
            .flat_map(|g| g["hooks"].as_array().cloned().unwrap_or_default())
            .filter_map(|h| h["command"].as_str().map(str::to_string))
            .filter(|c| c.contains("cop-hook"))
            .collect();
        if commands.is_empty() {
            missing.push(event);
        }
        for c in commands {
            if c != bin_text {
                wrong.push(format!("{event} runs {c}"));
            }
        }
    }
    if missing.is_empty() && wrong.is_empty() {
        line(
            t,
            "PASS",
            &format!("hook path: {} runs {bin_text}", path.display()),
            None,
        );
    } else {
        let mut detail = wrong;
        detail.extend(missing.iter().map(|e| format!("no {e} entry")));
        line(
            t,
            "FAIL",
            &format!("hook path in {}: {}", path.display(), detail.join("; ")),
            Some("agentcop install"),
        );
    }
}

fn check_binary(bin: &Path, t: &mut Tally) {
    if !bin.exists() {
        line(
            t,
            "FAIL",
            "installed hook ~/.agentcop/bin/cop-hook is missing",
            Some("agentcop install"),
        );
        return;
    }
    let version = Command::new(bin)
        .arg("--version")
        .output()
        .ok()
        .map(|o| String::from_utf8_lossy(&o.stdout).trim().to_string());
    let want = format!("cop-hook {}", env!("CARGO_PKG_VERSION"));
    if version.as_deref() != Some(want.as_str()) {
        line(
            t,
            "FAIL",
            &format!(
                "installed hook reports {:?}, this CLI is {want}",
                version.unwrap_or_default()
            ),
            Some("agentcop install (from the same build as this agentcop)"),
        );
        return;
    }
    // The CLI's own build of cop-hook, next to it: the installed copy must be identical to it.
    let sibling = std::env::current_exe()
        .ok()
        .and_then(|p| p.parent().map(|d| d.join("cop-hook")))
        .filter(|p| p.exists());
    match sibling {
        Some(sib) if sha256(&sib) != sha256(bin) => line(
            t,
            "FAIL",
            &format!(
                "installed hook differs from the build next to this agentcop ({})",
                sib.display()
            ),
            Some("agentcop install"),
        ),
        _ => line(t, "PASS", &format!("installed hook is {want}"), None),
    }
}

fn sha256(path: &Path) -> String {
    use sha2::{Digest, Sha256};
    fs::read(path)
        .map(|b| format!("{:x}", Sha256::digest(&b)))
        .unwrap_or_default()
}

fn check_canaries_installed(state: &Path, t: &mut Tally) {
    let policy = state.join("policy.toml");
    let Ok(text) = fs::read_to_string(&policy) else {
        line(
            t,
            "FAIL",
            "installed policy ~/.agentcop/policy.toml is missing",
            Some("agentcop install"),
        );
        return;
    };
    match canary_report(&text) {
        Ok(failed) if failed.is_empty() => line(t, "PASS", "policy canaries: every must-catch action is caught", None),
        Ok(failed) => line(
            t,
            "FAIL",
            &format!("policy canaries allow: {}", failed.join("; ")),
            Some("restore the default rule for them: copy policy/default.toml over ~/.agentcop/policy.toml, then agentcop install"),
        ),
        Err(e) => line(t, "FAIL", &format!("policy does not load: {e}"), Some("restore policy/default.toml")),
    }
}

/// Canary names the policy allows. Err when the policy does not load.
fn canary_report(text: &str) -> Result<Vec<&'static str>, String> {
    let policy: cop_policy::Policy = toml::from_str(text).map_err(|e| e.to_string())?;
    let judge = cop_policy::Judge::new(policy).map_err(|e| e.to_string())?;
    Ok(cop_policy::run_canaries(&judge)
        .into_iter()
        .filter(|r| !r.passed)
        .map(|r| r.name)
        .collect())
}

/// `agentcop policy check [FILE]`: canaries against one policy file (the installed one by default).
pub fn policy_check(file: Option<PathBuf>) -> Result<(), String> {
    let path = match file {
        Some(p) => p,
        None => dirs::home_dir()
            .ok_or("Failed to find home directory")?
            .join(".agentcop/policy.toml"),
    };
    let text = fs::read_to_string(&path).map_err(|e| format!("read {}: {e}", path.display()))?;
    let policy: cop_policy::Policy =
        toml::from_str(&text).map_err(|e| format!("policy does not load: {e}"))?;
    let judge =
        cop_policy::Judge::new(policy).map_err(|e| format!("policy does not compile: {e}"))?;
    let mut failed = 0;
    for r in cop_policy::run_canaries(&judge) {
        println!(
            "{}  {} -> {:?}",
            if r.passed { "PASS" } else { "FAIL" },
            r.name,
            r.verdict
        );
        if !r.passed {
            failed += 1;
        }
    }
    if failed > 0 {
        println!("{failed} canary action(s) allowed by {}", path.display());
        std::process::exit(1);
    }
    println!("all canaries caught by {}", path.display());
    Ok(())
}

fn check_chain(state: &Path, t: &mut Tally) {
    let evidence = state.join("evidence.db");
    if !evidence.exists() {
        line(
            t,
            "WARN",
            "no evidence chain yet (no hook call has been recorded)",
            Some("start a Claude Code session"),
        );
        return;
    }
    let store = match EvidenceStore::open_existing(&evidence) {
        Ok(s) => s,
        Err(e) => {
            line(
                t,
                "FAIL",
                &format!("evidence.db does not open: {e}"),
                Some("agentcop verify"),
            );
            return;
        }
    };
    if let Err(e) = store.verify() {
        line(
            t,
            "FAIL",
            &format!("evidence chain does not verify: {e}"),
            Some("agentcop verify (keep every archive; do not edit the chain)"),
        );
        return;
    }
    let rows = store.count().unwrap_or(0);
    match (store.anchor().ok().flatten(), latest_archive(state)) {
        (Some(anchor), Some(archive)) => {
            let ok = final_hash(&archive).ok().as_deref() == Some(anchor.as_str());
            if ok {
                line(
                    t,
                    "PASS",
                    &format!(
                        "evidence chain verifies ({rows} rows) and continues from {}",
                        archive.display()
                    ),
                    None,
                );
            } else {
                line(
                    t,
                    "FAIL",
                    "the chain does not continue from the newest archive",
                    Some("agentcop verify"),
                );
            }
        }
        _ => line(
            t,
            "PASS",
            &format!("evidence chain verifies ({rows} rows)"),
            None,
        ),
    }
}

fn check_heartbeat(state: &Path, t: &mut Tally) {
    let evidence = state.join("evidence.db");
    let last = EvidenceStore::open_existing(&evidence)
        .ok()
        .and_then(|s| s.find_by_hash_prefix("").ok())
        .and_then(|rows| {
            rows.into_iter().rfind(|r| {
                r.event_json
                    .contains("\"hook_event_name\":\"SessionStart\"")
            })
        });
    match last {
        Some(row) => line(t, "PASS", &format!("last session start (heartbeat): {}", row.timestamp), None),
        None => line(
            t,
            "WARN",
            "no session start recorded yet: silent days cannot be told from a dead hook",
            Some("agentcop install (registers the SessionStart heartbeat), then start a Claude Code session"),
        ),
    }
}

fn check_mode(state: &Path, t: &mut Tally) {
    let text = fs::read_to_string(state.join("policy.toml")).unwrap_or_default();
    let mode = toml::from_str::<cop_policy::Policy>(&text)
        .map(|p| p.mode)
        .unwrap_or_default();
    match mode {
        cop_policy::Mode::Enforce => line(t, "PASS", "mode: enforce (denials are enforced)", None),
        cop_policy::Mode::LogOnly => line(
            t,
            "WARN",
            "mode: log-only: nothing is blocked, the evidence only records what would be",
            Some(
                "set mode = \"enforce\" in ~/.agentcop/policy.toml when the log-only week is done",
            ),
        ),
    }
}

fn check_archives(state: &Path, t: &mut Tally) {
    let archives = crate::evidence_cmd::raw_archives(state);
    if archives.is_empty() {
        line(t, "PASS", "no raw-data archives on disk", None);
        return;
    }
    let bytes: u64 = archives
        .iter()
        .filter_map(|p| fs::metadata(p).ok())
        .map(|m| m.len())
        .sum();
    line(
        t,
        "WARN",
        &format!(
            "{} raw-data archive file(s) on disk ({} KB) hold raw commands",
            archives.len(),
            bytes / 1024
        ),
        Some("agentcop evidence purge-legacy (asks first)"),
    );
}
