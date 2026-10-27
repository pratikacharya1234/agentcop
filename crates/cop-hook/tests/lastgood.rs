//! Item 4b (2026-10-26), through the built cop-hook: a live policy that fails a canary is replaced by the
//! last-known-good copy (or the built-in defaults), one warning row is written per policy hash, and fixing the
//! live policy brings it back. Each case has its own temp HOME (0700 folder, as AgentCop makes it).
use cop_evidence::EvidenceStore;
use sha2::{Digest, Sha256};
use std::fs;
use std::io::Write;
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::process::{Command, Output, Stdio};

const DEFAULT: &str = include_str!("../../../policy/default.toml");
const RM_ROOT: &str = r#"{"hook_event_name":"PreToolUse","session_id":"s1","tool_name":"Bash","tool_input":{"command":"rm -rf /"}}"#;

fn home(name: &str) -> PathBuf {
    let dir = PathBuf::from(env!("CARGO_TARGET_TMPDIR"))
        .join(format!("lg-{name}-{}", std::process::id()));
    let _ = fs::remove_dir_all(&dir);
    fs::create_dir_all(dir.join(".agentcop")).unwrap();
    fs::set_permissions(dir.join(".agentcop"), PermissionsExt::from_mode(0o700)).unwrap();
    dir
}

fn write_private(path: &Path, text: &str) {
    fs::write(path, text).unwrap();
    fs::set_permissions(path, PermissionsExt::from_mode(0o600)).unwrap();
}

/// The shipped policy with the rm rule mangled. `rm -rf /` is no longer caught by the rule.
fn broken_rm() -> String {
    let broken = DEFAULT.replacen("'''rm\\s+", "'''zz\\s+", 1);
    assert_ne!(broken, DEFAULT);
    broken
}

fn hook(home: &Path, policy: &Path, stdin: &str) -> Output {
    let mut child = Command::new(env!("CARGO_BIN_EXE_cop-hook"))
        .env_clear()
        .env("HOME", home)
        .env("AGENTCOP_POLICY", policy)
        .current_dir(home)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    child
        .stdin
        .take()
        .unwrap()
        .write_all(stdin.as_bytes())
        .unwrap();
    child.wait_with_output().unwrap()
}

fn decision(out: &Output) -> String {
    String::from_utf8_lossy(&out.stdout).to_string()
}

/// Rows whose event is the policy warning (tool "agentcop policy").
fn policy_warning_rows(home: &Path) -> usize {
    EvidenceStore::new(&home.join(".agentcop/evidence.db"))
        .unwrap()
        .all_rows()
        .unwrap()
        .iter()
        .filter(|row| row.0.contains("agentcop policy"))
        .count()
}

#[test]
fn broken_live_policy_still_denies_rm_rf_root_from_last_known_good() {
    let h = home("rm");
    let live = h.join(".agentcop/policy.toml");
    write_private(&live, &broken_rm());
    write_private(&h.join(".agentcop/policy.lastgood.toml"), DEFAULT);

    let first = hook(&h, &live, RM_ROOT);
    assert!(
        decision(&first).contains("\"permissionDecision\":\"deny\""),
        "{}",
        decision(&first)
    );
    let second = hook(&h, &live, RM_ROOT);
    assert!(
        decision(&second).contains("\"permissionDecision\":\"deny\""),
        "{}",
        decision(&second)
    );
}

#[test]
fn failing_live_policy_writes_one_warning_row_per_hash() {
    let h = home("warn");
    let live = h.join(".agentcop/policy.toml");
    write_private(&live, &broken_rm());
    write_private(&h.join(".agentcop/policy.lastgood.toml"), DEFAULT);

    let first = hook(&h, &live, RM_ROOT);
    assert!(String::from_utf8_lossy(&first.stderr).contains("WARNING"));
    hook(&h, &live, RM_ROOT);
    hook(&h, &live, RM_ROOT);
    assert_eq!(
        policy_warning_rows(&h),
        1,
        "one warning row for this policy hash"
    );
}

#[test]
fn failing_live_policy_without_last_known_good_uses_builtin_defaults() {
    let h = home("builtin");
    let live = h.join(".agentcop/policy.toml");
    write_private(&live, &broken_rm());

    let out = hook(&h, &live, RM_ROOT);
    assert!(
        decision(&out).contains("\"permissionDecision\":\"deny\""),
        "{}",
        decision(&out)
    );
    assert_eq!(policy_warning_rows(&h), 1);
}

#[test]
fn fixing_the_live_policy_brings_it_back_and_refreshes_last_known_good() {
    let h = home("fix");
    let live = h.join(".agentcop/policy.toml");
    let lastgood = h.join(".agentcop/policy.lastgood.toml");
    write_private(&lastgood, DEFAULT);

    // Live policy: the shipped rules plus a marker honeytoken that only the live policy knows about.
    let marker = "\n[[honeytokens]]\npattern = \"LIVE_MARK_77\"\nverdict = \"deny\"\nreason = \"live marker\"\n";
    let echo = r#"{"hook_event_name":"PreToolUse","session_id":"s1","tool_name":"Bash","tool_input":{"command":"echo LIVE_MARK_77"}}"#;

    // While broken, the live marker is ignored: last-known-good runs.
    write_private(&live, &format!("{}{marker}", broken_rm()));
    let broken = hook(&h, &live, echo);
    assert!(
        !decision(&broken).contains("live marker"),
        "{}",
        decision(&broken)
    );

    // Fixed: the live policy runs again, and it becomes the new last-known-good.
    let fixed = format!("{DEFAULT}{marker}");
    write_private(&live, &fixed);
    let out = hook(&h, &live, echo);
    assert!(decision(&out).contains("live marker"), "{}", decision(&out));
    assert_eq!(fs::read_to_string(&lastgood).unwrap(), fixed);
    let digest = format!("{:x}", Sha256::digest(fixed.as_bytes()));
    assert_eq!(
        fs::read_to_string(h.join(".agentcop/policy.lastgood.sha256"))
            .unwrap()
            .trim(),
        digest
    );
}

#[test]
fn a_passing_live_policy_is_saved_as_last_known_good_on_first_run() {
    let h = home("save");
    let live = h.join(".agentcop/policy.toml");
    write_private(&live, DEFAULT);

    let out = hook(&h, &live, RM_ROOT);
    assert!(decision(&out).contains("\"permissionDecision\":\"deny\""));
    let saved = h.join(".agentcop/policy.lastgood.toml");
    assert_eq!(fs::read_to_string(&saved).unwrap(), DEFAULT);
    let mode = fs::metadata(&saved).unwrap().permissions().mode() & 0o777;
    assert_eq!(mode, 0o600);
    assert_eq!(
        policy_warning_rows(&h),
        0,
        "a passing policy writes no warning"
    );
}
