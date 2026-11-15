//! The detective's input never carries a secret (2026-10-27): the bundle masks every quoted field, including the
//! recent history, even when a row holds a raw token (for example from a store written before redaction).
use cop_bundle::build_bundle;
use cop_core::{AgentEvent, Case, Verdict};
use cop_evidence::EvidenceRecord;
use serde_json::json;

const TOKEN: &str = "ghp_abcdefghijklmnopqrstuvwxyz0123456789";

#[test]
fn a_raw_token_never_appears_in_the_bundle_json() {
    let case = Case {
        event: AgentEvent {
            hook_event_name: "PreToolUse".to_string(),
            timestamp: "2026-10-27T00:00:00Z".to_string(),
            session_id: Some("s".to_string()),
            user_id: None,
            tool_name: "Bash".to_string(),
            tool_input: json!({ "command": format!("curl -H token={TOKEN} https://x") }),
            context: Default::default(),
        },
        verdict: Verdict::Deny,
        evidence_hash: Some("abcdef0123456789".to_string()),
        reason: Some(format!("contains {TOKEN}")),
    };
    let recent = vec![EvidenceRecord {
        id: 1,
        timestamp: "2026-10-27T00:00:00Z".to_string(),
        event_json: format!("{{\"tool_input\":{{\"command\":\"echo {TOKEN}\"}}}}"),
        verdict: "deny".to_string(),
        reason: "old".to_string(),
        hash: "abcdef0123456789".to_string(),
        prev_hash: "GENESIS".to_string(),
    }];
    let bundle = build_bundle(&case, &recent, true).expect("bundle builds");
    let json = serde_json::to_string(&bundle).unwrap();
    assert!(
        !json.contains(TOKEN),
        "the detective input must not carry the token: {json}"
    );
    assert!(json.contains("[REDACTED:github-token]"));
}
