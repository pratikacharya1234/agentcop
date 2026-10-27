//! FP-1 follow-ups (2026-10-26), through the built cop-hook: extra secret names from the policy file (ADR 26), and
//! documented example keys written into a file (no flag). Each call is its own process, so the session flag must
//! persist on disk.
use std::fs;
use std::io::Write;
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::sync::atomic::{AtomicUsize, Ordering};

static COUNTER: AtomicUsize = AtomicUsize::new(0);
const DEFAULT: &str = include_str!("../../../policy/default.toml");

fn sandbox() -> (PathBuf, PathBuf) {
    let n = COUNTER.fetch_add(1, Ordering::SeqCst);
    let home =
        PathBuf::from(env!("CARGO_TARGET_TMPDIR")).join(format!("fp1f-{}-{n}", std::process::id()));
    let _ = fs::remove_dir_all(&home);
    fs::create_dir_all(home.join(".agentcop")).unwrap();
    fs::set_permissions(home.join(".agentcop"), PermissionsExt::from_mode(0o700)).unwrap();
    let work = home.join("work");
    fs::create_dir_all(&work).unwrap();
    (home, work)
}

/// The shipped policy with one extra secret name. Keys go before the first table, so they stay top-level.
fn policy_with_extra(home: &Path) -> PathBuf {
    let p = home.join("policy.toml");
    fs::write(
        &p,
        format!("sensitive_files_extra = [\"*.secret\"]\n{DEFAULT}"),
    )
    .unwrap();
    fs::set_permissions(&p, PermissionsExt::from_mode(0o600)).unwrap();
    p
}

fn call(home: &Path, policy: &Path, session: &str, event: serde_json::Value) -> (String, String) {
    let mut event = event;
    event["session_id"] = serde_json::json!(session);
    event["cwd"] = serde_json::json!(home);
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
        .write_all(event.to_string().as_bytes())
        .unwrap();
    let out = child.wait_with_output().unwrap();
    let text = String::from_utf8_lossy(&out.stdout).to_string();
    if text.trim().is_empty() {
        return (String::new(), String::new());
    }
    let v: serde_json::Value =
        serde_json::from_str(&text).unwrap_or_else(|_| panic!("bad output: {text}"));
    (
        v["hookSpecificOutput"]["permissionDecision"]
            .as_str()
            .unwrap_or("")
            .to_string(),
        v["hookSpecificOutput"]["permissionDecisionReason"]
            .as_str()
            .unwrap_or("")
            .to_string(),
    )
}

fn bash(home: &Path, policy: &Path, session: &str, command: &str) -> (String, String) {
    call(
        home,
        policy,
        session,
        serde_json::json!({"hook_event_name":"PreToolUse","tool_name":"Bash","tool_input":{"command":command}}),
    )
}

#[test]
fn an_extra_name_from_the_policy_is_a_secret_file() {
    let (home, _work) = sandbox();
    let policy = policy_with_extra(&home);
    let d = bash(&home, &policy, "x-extra", "cat config/app.secret");
    assert_eq!(d.0, "deny", "{d:?}");
    let next = bash(&home, &policy, "x-extra", "python3 -c \"print(1)\"");
    assert_eq!(next.0, "ask", "the extra name set the flag: {next:?}");
}

#[test]
fn an_extra_name_does_not_remove_a_built_in_name() {
    let (home, _work) = sandbox();
    let policy = policy_with_extra(&home);
    assert_eq!(bash(&home, &policy, "x-builtin", "cat .env").0, "deny");
}

#[test]
fn a_documented_example_key_written_to_a_file_sets_no_flag() {
    let (home, _work) = sandbox();
    let policy = policy_with_extra(&home);
    let w = call(
        &home,
        &policy,
        "x-example",
        serde_json::json!({"hook_event_name":"PreToolUse","tool_name":"Write","tool_input":{
            "file_path": home.join("work/notes.md"),
            "content": "aws_access_key_id = AKIAIOSFODNN7EXAMPLE\n"
        }}),
    );
    assert_eq!(w.0, "allow", "{w:?}");
    assert_eq!(
        bash(&home, &policy, "x-example", "python3 -c \"print(1)\"").0,
        "allow",
        "no flag"
    );
}

#[test]
fn a_real_looking_key_written_to_a_file_sets_the_flag() {
    let (home, _work) = sandbox();
    let policy = policy_with_extra(&home);
    let w = call(
        &home,
        &policy,
        "x-real",
        serde_json::json!({"hook_event_name":"PreToolUse","tool_name":"Write","tool_input":{
            "file_path": home.join("work/notes.md"),
            "content": "aws_access_key_id = AKIAZ9Q7K3M2P5R8T1WX\n"
        }}),
    );
    assert_eq!(w.0, "allow", "{w:?}");
    assert_eq!(
        bash(&home, &policy, "x-real", "python3 -c \"print(1)\"").0,
        "ask",
        "flag set"
    );
}
