//! Item 4 (2026-10-27), through the built cop-hook: the SessionStart heartbeat, the version flag, and the canary
//! warning when the policy file changes. Each case has its own temp HOME (0700 folder, as AgentCop makes it).
use cop_evidence::EvidenceStore;
use std::fs;
use std::io::Write;
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::process::{Command, Output, Stdio};

const DEFAULT: &str = include_str!("../../../policy/default.toml");

fn home(name: &str) -> PathBuf {
    let dir = PathBuf::from(env!("CARGO_TARGET_TMPDIR"))
        .join(format!("hb-{name}-{}", std::process::id()));
    let _ = fs::remove_dir_all(&dir);
    fs::create_dir_all(dir.join(".agentcop")).unwrap();
    fs::set_permissions(dir.join(".agentcop"), PermissionsExt::from_mode(0o700)).unwrap();
    dir
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

fn shipped_policy(home: &Path) -> PathBuf {
    let p = home.join("policy.toml");
    fs::write(&p, DEFAULT).unwrap();
    fs::set_permissions(&p, PermissionsExt::from_mode(0o600)).unwrap();
    p
}

#[test]
fn session_start_writes_one_heartbeat_row_and_prints_nothing() {
    let h = home("beat");
    let policy = shipped_policy(&h);
    let out = hook(
        &h,
        &policy,
        r#"{"hook_event_name":"SessionStart","session_id":"s1","source":"startup"}"#,
    );
    assert!(
        out.status.success(),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
    assert!(
        out.stdout.is_empty(),
        "a heartbeat is not a verdict: nothing on stdout"
    );
    let rows = EvidenceStore::new(&h.join(".agentcop/evidence.db"))
        .unwrap()
        .all_rows()
        .unwrap();
    assert_eq!(rows.len(), 1);
    assert!(
        rows[0].0.contains("\"hook_event_name\":\"SessionStart\""),
        "{}",
        rows[0].0
    );
}

#[test]
fn version_flag_reports_the_build_and_reads_no_stdin() {
    let out = Command::new(env!("CARGO_BIN_EXE_cop-hook"))
        .arg("--version")
        .output()
        .unwrap();
    assert!(out.status.success());
    assert_eq!(
        String::from_utf8_lossy(&out.stdout).trim(),
        format!("cop-hook {}", env!("CARGO_PKG_VERSION"))
    );
}

#[test]
fn a_policy_that_allows_a_canary_warns_once_per_change() {
    let h = home("canary");
    let broken = DEFAULT.replacen("pattern = '''rm", "pattern = '''''rm", 1);
    let p = h.join("policy.toml");
    fs::write(&p, broken).unwrap();
    fs::set_permissions(&p, PermissionsExt::from_mode(0o600)).unwrap();
    let call = r#"{"hook_event_name":"PreToolUse","session_id":"c","tool_name":"Bash","tool_input":{"command":"ls"}}"#;
    let first = hook(&h, &p, call);
    let err = String::from_utf8_lossy(&first.stderr).to_string();
    assert!(
        err.contains("WARNING: the loaded policy allows") && err.contains("rm -rf /"),
        "{err}"
    );
    let second = hook(&h, &p, call);
    assert!(
        !String::from_utf8_lossy(&second.stderr).contains("WARNING: the loaded policy"),
        "warned once per change"
    );
    let rows = EvidenceStore::new(&h.join(".agentcop/evidence.db"))
        .unwrap()
        .all_rows()
        .unwrap();
    assert!(
        rows.iter().any(|(e, _)| e.contains("PolicyCheck")),
        "the warning is recorded"
    );
}
