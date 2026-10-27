//! C2-R3 end to end: a Bash command that runs a script file is judged by the script's contents.
//!
//! Each scenario has its own temp HOME (so session state is shared only inside one scenario)
//! and its own working directory, because the hook resolves relative script paths from it.
//!
//! PLAN:
//! 1. A script the agent wrote this session (Write tool or a shell write) asks, even if clean.
//! 2. A script's contents are judged: a destructive line denies, and the reason names the line.
//! 3. Nested `source` calls are followed up to 3 levels; deeper asks.
//! 4. Missing or oversize scripts ask.
//! 5. Destructive commands with a variable or glob target ask; with a literal target they are allowed.

use serde_json::{json, Value};
use std::fs;
use std::io::Write;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};

struct Scenario {
    home: PathBuf,
    cwd: PathBuf,
    session: String,
}

fn scratch(name: &str) -> PathBuf {
    let dir = PathBuf::from(env!("CARGO_TARGET_TMPDIR")).join(format!("c2r3-{name}"));
    let _ = fs::remove_dir_all(&dir);
    fs::create_dir_all(&dir).unwrap();
    dir
}

fn scenario(name: &str, cwd: &Path) -> Scenario {
    let home = scratch(&format!("home-{name}"));
    fs::create_dir_all(home.join(".agentcop")).unwrap();
    Scenario {
        home,
        cwd: cwd.to_path_buf(),
        session: format!("c2r3-{name}"),
    }
}

/// Run the built hook for one tool call. Returns (permissionDecision, reason).
fn run(s: &Scenario, tool: &str, input: Value) -> (String, String) {
    let event = json!({
        "hook_event_name": "PreToolUse",
        "session_id": s.session,
        "timestamp": "2026-10-27T10:00:00Z",
        "tool_name": tool,
        "tool_input": input,
    });
    let mut child = Command::new(env!("CARGO_BIN_EXE_cop-hook"))
        .env_clear()
        .env("HOME", &s.home)
        .env(
            "AGENTCOP_POLICY",
            concat!(env!("CARGO_MANIFEST_DIR"), "/../../policy/default.toml"),
        )
        .current_dir(&s.cwd)
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
    let json: Value = serde_json::from_slice(&out.stdout)
        .unwrap_or_else(|e| panic!("no JSON verdict for {event}: {e}"));
    let specific = &json["hookSpecificOutput"];
    (
        specific["permissionDecision"]
            .as_str()
            .unwrap_or("")
            .to_string(),
        specific["permissionDecisionReason"]
            .as_str()
            .unwrap_or("")
            .to_string(),
    )
}

fn bash(s: &Scenario, cmd: &str) -> (String, String) {
    run(s, "Bash", json!({ "command": cmd }))
}

fn write_file(path: &Path, text: &str) {
    fs::write(path, text).unwrap();
}

#[test]
fn script_written_by_the_agent_that_removes_home_is_denied() {
    let dir = scratch("evil-dir");
    let s = scenario("evil", &dir);
    let file = dir.join("evil.sh");
    write_file(&file, "rm -rf ~\n");
    // The Write tool call itself is recorded by the hook, as the agent did it.
    run(
        &s,
        "Write",
        json!({ "file_path": file.to_str().unwrap(), "content": "rm -rf ~\n" }),
    );
    let (decision, reason) = bash(&s, "bash evil.sh");
    assert_eq!(decision, "deny", "{reason}");
}

#[test]
fn clean_script_written_by_the_agent_this_session_asks() {
    let dir = scratch("clean-dir");
    let s = scenario("clean", &dir);
    let file = dir.join("clean.sh");
    write_file(&file, "echo hello\n");
    run(
        &s,
        "Write",
        json!({ "file_path": file.to_str().unwrap(), "content": "echo hello\n" }),
    );
    let (decision, reason) = bash(&s, "bash clean.sh");
    assert_eq!(decision, "ask", "{reason}");
}

#[test]
fn script_changed_by_a_shell_write_this_session_asks() {
    let dir = scratch("shellwrite-dir");
    let s = scenario("shellwrite", &dir);
    bash(&s, "echo 'echo hi' > made.sh");
    let (decision, reason) = bash(&s, "bash made.sh");
    assert_eq!(decision, "ask", "{reason}");
}

#[test]
fn existing_clean_repo_script_is_allowed() {
    let repo = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../..");
    let repo = repo.canonicalize().unwrap();
    let s = scenario("check-sh", &repo);
    let (decision, reason) = bash(&s, "./scripts/check.sh");
    assert_eq!(decision, "allow", "{reason}");
}

#[test]
fn destructive_line_in_a_script_names_the_line_and_denies() {
    let dir = scratch("line-dir");
    let s = scenario("line", &dir);
    write_file(&dir.join("lines.sh"), "echo ok\nrm -rf /\n");
    let (decision, reason) = bash(&s, "bash lines.sh");
    assert_eq!(decision, "deny", "{reason}");
    assert!(reason.contains("lines.sh line 2"), "{reason}");
}

#[test]
fn source_chain_reaching_rm_root_is_denied() {
    let dir = scratch("chain-dir");
    let s = scenario("chain", &dir);
    write_file(&dir.join("a.sh"), "source b.sh\n");
    write_file(&dir.join("b.sh"), "rm -rf /\n");
    let (decision, reason) = bash(&s, "source a.sh");
    assert_eq!(decision, "deny", "{reason}");
}

#[test]
fn nesting_deeper_than_three_levels_asks() {
    let dir = scratch("deep-dir");
    let s = scenario("deep", &dir);
    write_file(&dir.join("s1.sh"), "source s2.sh\n");
    write_file(&dir.join("s2.sh"), "source s3.sh\n");
    write_file(&dir.join("s3.sh"), "source s4.sh\n");
    write_file(&dir.join("s4.sh"), "echo ok\n");
    let (decision, reason) = bash(&s, "bash s1.sh");
    assert_eq!(decision, "ask", "{reason}");
}

#[test]
fn script_over_256_kb_asks() {
    let dir = scratch("big-dir");
    let s = scenario("big", &dir);
    write_file(&dir.join("big.sh"), &"echo x\n".repeat(300 * 1024 / 7));
    let (decision, reason) = bash(&s, "bash big.sh");
    assert_eq!(decision, "ask", "{reason}");
}

#[test]
fn missing_script_asks() {
    let dir = scratch("missing-dir");
    let s = scenario("missing", &dir);
    let (decision, reason) = bash(&s, "bash nope.sh");
    assert_eq!(decision, "ask", "{reason}");
}

#[test]
fn rm_with_variable_target_asks() {
    let dir = scratch("var-dir");
    let s = scenario("var", &dir);
    let (decision, reason) = bash(&s, "rm -rf $BUILD_DIR");
    assert_eq!(decision, "ask", "{reason}");
}

#[test]
fn rm_with_literal_target_is_allowed() {
    let dir = scratch("literal-dir");
    let s = scenario("literal", &dir);
    let (decision, reason) = bash(&s, "rm -rf ./build");
    assert_eq!(decision, "allow", "{reason}");
}
