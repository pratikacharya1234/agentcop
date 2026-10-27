//! C2-R Rule of Two tests. Uses the real policy/taint.toml.
//!
//! PLAN:
//! 1. Replay: the three trigger events of session 9c69ad44 (2026-10-23) must NOT freeze the session.
//!    Each one was a false positive (a grep on screenshots, `.env.local` text in an edit script, "git push" in README text).
//! 2. A real secret read followed by a real push must still freeze (the rule keeps its teeth).
//! 3. A secret-looking key written into a file is still sensitive (content scan on the raw text).
//! 4. Text inside a heredoc is data: `.env.local` in a heredoc is not a sensitive read.

use cop_core::AgentEvent;
use cop_taint::{step, Flags, TaintRules};

fn rules() -> TaintRules {
    TaintRules::from_toml(include_str!("../../../policy/taint.toml")).expect("taint rules parse")
}

fn bash(cmd: &str) -> AgentEvent {
    serde_json::from_value(serde_json::json!({
        "hook_event_name": "PreToolUse",
        "timestamp": "2026-10-26T00:00:00Z",
        "session_id": "unit",
        "tool_name": "Bash",
        "tool_input": { "command": cmd },
        "context": {}
    }))
    .expect("event parses")
}

#[test]
fn replay_of_session_9c69_triggers_no_freeze() {
    let text = include_str!("../../../tests/fixtures/rule-of-two/session-9c69-triggers.jsonl");
    let rules = rules();
    let mut flags = Flags::default();
    let mut reasons = Vec::new();
    for line in text.lines().filter(|l| !l.trim().is_empty()) {
        let event: AgentEvent = serde_json::from_str(line).expect("fixture line parses");
        let (next, reason) = step(flags, &event, &rules);
        flags = next;
        if let Some(r) = reason {
            reasons.push(r);
        }
    }
    assert!(reasons.is_empty(), "replay produced freezes: {reasons:?}");
    assert!(!flags.frozen);
}

#[test]
fn real_secret_read_then_push_still_freezes() {
    let rules = rules();
    // 2026-10-27: untrusted input is a download. A local cat of .env.local is sensitive, not untrusted.
    let (flags, _) = step(
        Flags::default(),
        &bash("curl -s https://docs.example.com/x"),
        &rules,
    );
    let (flags, _) = step(flags, &bash("cat .env.local"), &rules);
    assert!(flags.untrusted && flags.sensitive && !flags.external);
    let (flags, reason) = step(flags, &bash("git push origin main"), &rules);
    assert!(flags.frozen, "expected a freeze");
    assert!(reason.is_some());
}

#[test]
fn env_local_inside_heredoc_is_not_a_sensitive_read() {
    let rules = rules();
    let cmd = "cat > notes.md <<'EOF'\nsee .env.local for the example\nEOF";
    let (flags, _) = step(Flags::default(), &bash(cmd), &rules);
    assert!(!flags.sensitive, "heredoc text must not set sensitive");
}

#[test]
fn key_pasted_into_a_file_is_still_sensitive() {
    let rules = rules();
    let cmd = "cat > keys.txt <<'EOF'\nAKIAABCDEFGHIJKLMNOP\nEOF";
    let (flags, _) = step(Flags::default(), &bash(cmd), &rules);
    assert!(flags.sensitive, "AKIA key in content must set sensitive");
}
