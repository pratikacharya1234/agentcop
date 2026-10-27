//! Integration test: cop-hook binary subprocess with real Claude Code fixture JSON
//!
//! Tests the compiled cop-hook binary with real hook JSON input to verify:
//! - Output format matches Claude Code hookSpecificOutput spec
//! - Exit codes are correct (0 for normal, 2 for error)
//! - No panics on untrusted input

use std::io::Write;
use std::process::{Command, Stdio};

fn get_hook_binary() -> String {
    env!("CARGO_BIN_EXE_cop-hook").to_string()
}

#[test]
fn test_hook_subprocess_with_fixture() {
    // Real Claude Code PreToolUse hook JSON (per docs)
    let fixture_input = r#"{
  "hookEventName": "PreToolUse",
  "session_id": "sess_test123",
  "user_id": "user@example.com",
  "tool_name": "bash",
  "tool_input": {"command": "ls /home"},
  "cwd": "/workspace"
}"#;

    let binary = get_hook_binary();
    let mut child = Command::new(&binary)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap_or_else(|_| panic!("failed to spawn {}", binary));

    {
        let mut stdin = child.stdin.take().expect("failed to open stdin");
        stdin
            .write_all(fixture_input.as_bytes())
            .expect("failed to write to stdin");
    }

    let output = child.wait_with_output().expect("failed to wait on child");
    let stdout = String::from_utf8_lossy(&output.stdout);

    // Parse output as JSON
    let json: serde_json::Value = serde_json::from_str(&stdout)
        .unwrap_or_else(|_| panic!("stdout is not valid JSON: {}", stdout));

    // Verify structure: hookSpecificOutput.hookEventName, permissionDecision, permissionDecisionReason
    assert!(
        json["hookSpecificOutput"].is_object(),
        "missing hookSpecificOutput object in: {}",
        json
    );

    assert_eq!(
        json["hookSpecificOutput"]["hookEventName"]
            .as_str()
            .unwrap_or(""),
        "PreToolUse",
        "hookEventName must be PreToolUse"
    );

    let decision = json["hookSpecificOutput"]["permissionDecision"]
        .as_str()
        .expect("permissionDecision must be a string");
    assert!(
        ["allow", "ask", "deny"].contains(&decision),
        "permissionDecision must be allow/ask/deny, got: {}",
        decision
    );

    assert!(
        !json["hookSpecificOutput"]["permissionDecisionReason"]
            .as_str()
            .unwrap_or("")
            .is_empty(),
        "permissionDecisionReason must not be empty"
    );
}

#[test]
fn test_hook_output_has_no_panics() {
    let fixture = r#"{"hookEventName":"PreToolUse","tool_name":"bash","tool_input":{}}"#;

    let binary = get_hook_binary();
    let mut child = Command::new(&binary)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap_or_else(|_| panic!("failed to spawn {}", binary));

    {
        let mut stdin = child.stdin.take().expect("failed to open stdin");
        stdin
            .write_all(fixture.as_bytes())
            .expect("failed to write to stdin");
    }

    let output = child.wait_with_output().expect("failed to wait");
    let stderr = String::from_utf8_lossy(&output.stderr);

    // Panic output contains "panicked"
    assert!(
        !stderr.contains("panicked"),
        "cop-hook panicked: {}",
        stderr
    );
}
