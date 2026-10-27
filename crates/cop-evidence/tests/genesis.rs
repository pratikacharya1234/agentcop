//! A second genesis write must not add a second anchor (2026-10-27): parallel hooks may both start a chain.
use cop_core::{AgentEvent, Case, Verdict};
use cop_evidence::EvidenceStore;
use std::collections::HashMap;

fn genesis() -> Case {
    Case {
        event: AgentEvent {
            hook_event_name: "Genesis".to_string(),
            timestamp: "2026-10-27T00:00:00Z".to_string(),
            session_id: None,
            user_id: None,
            tool_name: "agentcop evidence".to_string(),
            tool_input: serde_json::json!({"archived_final_hash": "abc"}),
            context: HashMap::new(),
        },
        verdict: Verdict::Allow,
        evidence_hash: None,
        reason: Some("test".to_string()),
    }
}

#[test]
fn a_second_genesis_is_refused_and_the_chain_still_verifies() {
    let dir = std::path::PathBuf::from(env!("CARGO_TARGET_TMPDIR"))
        .join(format!("genesis-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    let store = EvidenceStore::new(&dir.join("evidence.db")).unwrap();
    assert!(store.start_after(&genesis(), "", "abc").unwrap().is_some());
    assert!(
        store.start_after(&genesis(), "", "abc").unwrap().is_none(),
        "the second genesis is refused"
    );
    assert_eq!(store.count().unwrap(), 1);
    store.verify().expect("one genesis, valid chain");
}
