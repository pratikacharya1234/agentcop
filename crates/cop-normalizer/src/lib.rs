//! Event normalizer: unify hook, eBPF, and proxy logs into AgentEvent
//!
//! PLAN:
//! 1. Normalizer::from_json() accepts any sensor JSON
//! 2. Detects format (PreToolUse, Syscall, ProxyLog)
//! 3. Converts to unified AgentEvent
//! 4. Fills missing fields with defaults
//! 5. Tests: all three formats, missing fields, invalid JSON

use chrono::Utc;
use cop_core::AgentEvent;
use serde_json::{json, Value};

/// Event normalizer for multiple sensor formats
pub struct Normalizer;

impl Normalizer {
    /// Parse JSON from any sensor and convert to AgentEvent
    pub fn from_json(json_str: &str) -> Result<AgentEvent, String> {
        let value: Value =
            serde_json::from_str(json_str).map_err(|e| format!("Invalid JSON: {}", e))?;

        // Detect format by looking at key fields
        if value.get("hook_type").is_some() {
            // PreToolUse hook format
            Self::parse_pretooluse(&value)
        } else if value.get("syscall").is_some() || value.get("pid").is_some() {
            // eBPF syscall format
            Self::parse_ebpf(&value)
        } else if value.get("method").is_some() || value.get("path").is_some() {
            // Proxy log format
            Self::parse_proxy(&value)
        } else {
            // Try to parse directly as AgentEvent
            serde_json::from_value(value).map_err(|e| format!("Unknown format: {}", e))
        }
    }

    /// Parse PreToolUse hook JSON (what cop-hook produces)
    fn parse_pretooluse(value: &Value) -> Result<AgentEvent, String> {
        Ok(AgentEvent {
            hook_event_name: value
                .get("hook_type")
                .and_then(|v| v.as_str())
                .unwrap_or("PreToolUse")
                .to_string(),
            timestamp: value
                .get("timestamp")
                .and_then(|v| v.as_str())
                .map(|s| s.to_string())
                .unwrap_or_else(|| Utc::now().to_rfc3339()),
            session_id: value
                .get("session_id")
                .and_then(|v| v.as_str())
                .map(String::from),
            user_id: value
                .get("user_id")
                .and_then(|v| v.as_str())
                .map(String::from),
            tool_name: value
                .get("tool_name")
                .and_then(|v| v.as_str())
                .ok_or("Missing tool_name")?
                .to_string(),
            tool_input: value.get("tool_input").cloned().unwrap_or(json!({})),
            context: value
                .get("context")
                .and_then(|v| v.as_object())
                .map(|o| o.iter().map(|(k, v)| (k.clone(), v.clone())).collect())
                .unwrap_or_default(),
        })
    }

    /// Parse eBPF syscall log
    fn parse_ebpf(value: &Value) -> Result<AgentEvent, String> {
        let syscall = value
            .get("syscall")
            .and_then(|v| v.as_str())
            .unwrap_or("execve");

        let args = value
            .get("args")
            .and_then(|v| v.as_array())
            .map(|arr| json!(arr.iter().map(|a| a.to_string()).collect::<Vec<_>>()))
            .unwrap_or(json!([]));

        Ok(AgentEvent {
            hook_event_name: "Syscall".to_string(),
            timestamp: value
                .get("timestamp")
                .and_then(|v| v.as_str())
                .map(|s| s.to_string())
                .unwrap_or_else(|| Utc::now().to_rfc3339()),
            session_id: value
                .get("session_id")
                .and_then(|v| v.as_str())
                .map(String::from),
            user_id: value
                .get("uid")
                .and_then(|v| v.as_u64())
                .map(|u| u.to_string()),
            tool_name: syscall.to_string(),
            tool_input: json!({"syscall": syscall, "args": args}),
            context: value
                .get("context")
                .and_then(|v| v.as_object())
                .map(|o| o.iter().map(|(k, v)| (k.clone(), v.clone())).collect())
                .unwrap_or_default(),
        })
    }

    /// Parse HTTP proxy log
    fn parse_proxy(value: &Value) -> Result<AgentEvent, String> {
        let method = value
            .get("method")
            .and_then(|v| v.as_str())
            .unwrap_or("GET");
        let path = value.get("path").and_then(|v| v.as_str()).unwrap_or("/");

        Ok(AgentEvent {
            hook_event_name: "Proxy".to_string(),
            timestamp: value
                .get("timestamp")
                .and_then(|v| v.as_str())
                .map(|s| s.to_string())
                .unwrap_or_else(|| Utc::now().to_rfc3339()),
            session_id: value
                .get("session_id")
                .and_then(|v| v.as_str())
                .map(String::from),
            user_id: value
                .get("user_id")
                .and_then(|v| v.as_str())
                .map(String::from),
            tool_name: format!("{} {}", method, path),
            tool_input: json!({"method": method, "path": path, "body": value.get("body")}),
            context: value
                .get("context")
                .and_then(|v| v.as_object())
                .map(|o| o.iter().map(|(k, v)| (k.clone(), v.clone())).collect())
                .unwrap_or_default(),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_pretooluse_hook_format() {
        let json = r#"{
            "hook_type": "PreToolUse",
            "timestamp": "2026-10-20T10:00:00Z",
            "session_id": "s123",
            "user_id": "u456",
            "tool_name": "bash",
            "tool_input": {"command": "echo hello"},
            "context": {}
        }"#;

        let event = Normalizer::from_json(json).expect("Parse failed");
        assert_eq!(event.hook_event_name, "PreToolUse");
        assert_eq!(event.tool_name, "bash");
        assert!(event.tool_input.get("command").is_some());
    }

    #[test]
    fn parse_ebpf_syscall_format() {
        let json = r#"{
            "syscall": "execve",
            "timestamp": "2026-10-20T10:00:00Z",
            "args": ["ls", "-la"],
            "uid": 1000
        }"#;

        let event = Normalizer::from_json(json).expect("Parse failed");
        assert_eq!(event.hook_event_name, "Syscall");
        assert_eq!(event.tool_name, "execve");
        assert_eq!(event.user_id, Some("1000".to_string()));
    }

    #[test]
    fn parse_proxy_log_format() {
        let json = r#"{
            "method": "POST",
            "path": "/api/agent/execute",
            "timestamp": "2026-10-20T10:00:00Z",
            "user_id": "user@example.com"
        }"#;

        let event = Normalizer::from_json(json).expect("Parse failed");
        assert_eq!(event.hook_event_name, "Proxy");
        assert!(event.tool_name.contains("POST"));
        assert!(event.tool_name.contains("/api/agent/execute"));
    }

    #[test]
    fn missing_optional_fields_get_defaults() {
        let json = r#"{
            "hook_type": "PreToolUse",
            "tool_name": "bash",
            "tool_input": {}
        }"#;

        let event = Normalizer::from_json(json).expect("Parse failed");
        assert!(!event.timestamp.is_empty()); // Auto-filled
        assert!(event.session_id.is_none());
        assert!(event.user_id.is_none());
    }

    #[test]
    fn missing_required_field_returns_error() {
        let json = r#"{
            "hook_type": "PreToolUse"
        }"#;

        let result = Normalizer::from_json(json);
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("tool_name"));
    }

    #[test]
    fn invalid_json_returns_error() {
        let json = "not json at all";
        let result = Normalizer::from_json(json);
        assert!(result.is_err());
    }

    #[test]
    fn unknown_format_tries_direct_parse() {
        let json = r#"{
            "unknown_field": "value"
        }"#;

        let result = Normalizer::from_json(json);
        // Should fail because required fields are missing
        assert!(result.is_err());
    }
}
