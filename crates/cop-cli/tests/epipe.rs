//! FP-1 (2026-10-26): a CLI command whose output is cut short (`agentcop cases | head -1`) exits quietly. It does not
//! panic with "failed printing to stdout: Broken pipe".
use cop_core::{AgentEvent, Case, Verdict};
use cop_evidence::EvidenceStore;
use std::collections::HashMap;
use std::fs;
use std::path::PathBuf;
use std::process::Command;

#[test]
fn piping_a_long_listing_into_head_exits_without_a_panic() {
    let home =
        PathBuf::from(env!("CARGO_TARGET_TMPDIR")).join(format!("epipe-{}", std::process::id()));
    let _ = fs::remove_dir_all(&home);
    fs::create_dir_all(home.join(".agentcop")).unwrap();
    let store = EvidenceStore::new(&home.join(".agentcop/evidence.db")).unwrap();
    for i in 0..2000 {
        let case = Case {
            event: AgentEvent {
                hook_event_name: "PreToolUse".to_string(),
                timestamp: String::new(),
                session_id: Some("sess".to_string()),
                user_id: None,
                tool_name: "Bash".to_string(),
                tool_input: serde_json::json!({ "command": format!("echo {i}") }),
                context: HashMap::new(),
            },
            verdict: Verdict::Allow,
            evidence_hash: None,
            reason: Some(
                "No rules matched, padded so the listing is long enough to fill a pipe".to_string(),
            ),
        };
        store.append(&case).unwrap();
    }
    let bin = env!("CARGO_BIN_EXE_agentcop");
    let out = Command::new("sh")
        .arg("-c")
        .arg(format!("'{bin}' cases | head -1"))
        .env_clear()
        .env("HOME", &home)
        .output()
        .unwrap();
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(out.status.success(), "{stderr}");
    assert!(!stderr.contains("panicked"), "{stderr}");
    assert!(!stderr.contains("Broken pipe"), "{stderr}");
}
