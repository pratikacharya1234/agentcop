//! Step 0 of item 3 (2026-10-27): which non-Bash tool calls are external actions. Uses the shipped taint.toml.
//!
//! PLAN:
//! 1. An MCP call whose name matches a send pattern (taint.toml) is external, with no secret held.
//! 2. An MCP call that does not match, with no secret held, is not external.
//! 3. A web request is external only once the session holds a secret.
//! 4. Every MCP call is untrusted input.

use cop_core::AgentEvent;
use cop_taint::{classify, Flags, TaintRules};
use serde_json::json;
use std::collections::HashMap;

fn rules() -> TaintRules {
    TaintRules::from_toml(include_str!("../../../policy/taint.toml")).expect("taint rules parse")
}

fn call(tool: &str, input: serde_json::Value) -> AgentEvent {
    AgentEvent {
        hook_event_name: "PreToolUse".to_string(),
        timestamp: "2026-10-27T00:00:00Z".to_string(),
        session_id: Some("ext".to_string()),
        user_id: None,
        tool_name: tool.to_string(),
        tool_input: input,
        context: HashMap::new(),
    }
}

#[test]
fn mcp_send_named_tool_is_external() {
    let f = classify(
        &call("mcp__slack__post_message", json!({"text": "hi"})),
        &rules(),
    );
    assert!(f.external && f.untrusted);
}

#[test]
fn mcp_tool_without_a_send_name_is_not_external_without_a_secret() {
    let f = classify(&call("mcp__notes__search", json!({"query": "x"})), &rules());
    assert!(!f.external && f.untrusted);
}

#[test]
fn web_fetch_is_external_only_when_the_session_holds_a_secret() {
    let r = rules();
    let plain = classify(
        &call("WebFetch", json!({"url": "https://docs.example.com/"})),
        &r,
    );
    assert!(!plain.external && plain.untrusted);
    let held = Flags {
        sensitive: true,
        ..Flags::default()
    };
    let with_secret = cop_taint::classify_with(
        &call("WebFetch", json!({"url": "https://x.example.com/"})),
        &r,
        &held,
    );
    assert!(with_secret.external);
}
