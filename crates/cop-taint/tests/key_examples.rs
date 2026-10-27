//! FP-1 follow-up (2026-10-26): a key-shaped string written into a file sets the sensitive flag, except the
//! documented example keys (the AWS documentation key, and any AKIA... key ending in EXAMPLE). A real-looking key
//! still sets it.
use cop_core::AgentEvent;
use cop_taint::{classify, TaintRules};
use std::collections::HashMap;

fn rules() -> TaintRules {
    TaintRules::from_toml(include_str!("../../../policy/taint.toml")).unwrap()
}

fn write_event(content: &str) -> AgentEvent {
    AgentEvent {
        hook_event_name: "PreToolUse".to_string(),
        timestamp: String::new(),
        session_id: Some("k".to_string()),
        user_id: None,
        tool_name: "Write".to_string(),
        tool_input: serde_json::json!({ "file_path": "/tmp/notes.md", "content": content }),
        context: HashMap::new(),
    }
}

fn bash_event(command: &str) -> AgentEvent {
    AgentEvent {
        tool_name: "Bash".to_string(),
        tool_input: serde_json::json!({ "command": command }),
        ..write_event("")
    }
}

#[test]
fn the_aws_documentation_key_sets_no_flag() {
    let flags = classify(
        &write_event("aws_access_key_id = AKIAIOSFODNN7EXAMPLE\n"),
        &rules(),
    );
    assert!(!flags.sensitive);
}

#[test]
fn any_akia_key_ending_in_example_sets_no_flag() {
    let flags = classify(&write_event("key AKIAABCDEFGHIEXAMPLE\n"), &rules());
    assert!(!flags.sensitive);
}

#[test]
fn a_real_looking_key_sets_the_flag() {
    let flags = classify(&write_event("key AKIAZ9Q7K3M2P5R8T1WX\n"), &rules());
    assert!(flags.sensitive);
}

#[test]
fn a_documented_key_in_a_bash_heredoc_sets_no_flag() {
    let cmd = "cat > keys.txt <<'EOF'\nAKIAIOSFODNN7EXAMPLE\nEOF";
    assert!(!classify(&bash_event(cmd), &rules()).sensitive);
}

#[test]
fn a_real_looking_key_in_a_bash_command_sets_the_flag() {
    let cmd = "echo AKIAZ9Q7K3M2P5R8T1WX > keys.txt";
    assert!(classify(&bash_event(cmd), &rules()).sensitive);
}
