//! Shared types for AgentCop: AgentEvent, Verdict, Case
//!
//! PLAN:
//! 1. Define AgentEvent struct: tool_name, tool_input, context metadata
//! 2. Define Verdict enum: Allow, Ask, Deny with optional reason
//! 3. Define Case struct: event + verdict + evidence hash
//! 4. Add serde for JSON parsing/serialization; ignore unknown fields
//! 5. Parse real Claude Code PreToolUse JSON fixtures
//! 6. Error handling: malformed input → Err, never panic

use serde::{Deserialize, Serialize};
use std::collections::HashMap;

/// A single action an agent attempted (what they said they would do)
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AgentEvent {
    #[serde(alias = "hook_type")]
    pub hook_event_name: String,
    #[serde(default)]
    pub timestamp: String,
    pub session_id: Option<String>,
    pub user_id: Option<String>,
    pub tool_name: String,
    pub tool_input: serde_json::Value,
    #[serde(default)]
    pub context: HashMap<String, serde_json::Value>,
}

/// The judge's verdict on an event
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub enum Verdict {
    Allow,
    Ask,
    Deny,
}

/// A case: the full record of one event, its verdict, and evidence hash
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Case {
    pub event: AgentEvent,
    pub verdict: Verdict,
    pub evidence_hash: Option<String>,
    pub reason: Option<String>,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_simple_fixture() {
        let json = r#"{
          "hook_type": "PreToolUse",
          "timestamp": "2026-10-20T14:30:00Z",
          "session_id": "sess_abc123",
          "user_id": "user_xyz",
          "tool_name": "bash",
          "tool_input": {
            "command": "echo hello"
          },
          "context": {
            "current_directory": "/home/user/project"
          }
        }"#;

        let event: Result<AgentEvent, _> = serde_json::from_str(json);
        assert!(event.is_ok());
        let event = event.unwrap();
        assert_eq!(event.tool_name, "bash");
        assert_eq!(event.session_id, Some("sess_abc123".to_string()));
    }

    #[test]
    fn ignore_unknown_fields() {
        let json = r#"{
          "hook_type": "PreToolUse",
          "timestamp": "2026-10-20T14:30:00Z",
          "tool_name": "bash",
          "tool_input": {},
          "context": {},
          "unknown_field": "should_be_ignored",
          "another_unknown": 12345
        }"#;

        let event: Result<AgentEvent, _> = serde_json::from_str(json);
        assert!(event.is_ok());
    }

    #[test]
    fn malformed_missing_tool_name_returns_error() {
        let json = r#"{
          "hook_type": "PreToolUse",
          "timestamp": "2026-10-20T14:30:00Z",
          "tool_input": {}
        }"#;

        let event: Result<AgentEvent, _> = serde_json::from_str(json);
        assert!(event.is_err());
    }

    #[test]
    fn garbage_input_returns_error() {
        let garbage = "not valid json at all {{{";
        let event: Result<AgentEvent, _> = serde_json::from_str(garbage);
        assert!(event.is_err());
    }

    #[test]
    fn verdict_all_variants_exist() {
        let _ = Verdict::Allow;
        let _ = Verdict::Ask;
        let _ = Verdict::Deny;
    }

    #[test]
    fn verdict_serializes() {
        let v = Verdict::Deny;
        let json = serde_json::to_string(&v).unwrap();
        assert_eq!(json, "\"deny\"");
    }

    #[test]
    fn case_with_event_and_verdict() {
        let event: AgentEvent = serde_json::from_str(
            r#"{
          "hook_type": "PreToolUse",
          "timestamp": "2026-10-20T14:30:00Z",
          "tool_name": "bash",
          "tool_input": {},
          "context": {}
        }"#,
        )
        .unwrap();

        let case = Case {
            event: event.clone(),
            verdict: Verdict::Deny,
            evidence_hash: Some("abc123".to_string()),
            reason: Some("Matches deny rule".to_string()),
        };

        assert_eq!(case.verdict, Verdict::Deny);
        assert_eq!(case.event.tool_name, "bash");
    }
}
