//! Every verdict names its case, so a person can find it with `agentcop cases` and `agentcop fix`.
//! Gate A asks for this: the blocked `volume delete prod` must show a case number.

use cop_evidence::EvidenceStore;
use std::fs;
use std::io::Write;
use std::path::PathBuf;
use std::process::{Command, Stdio};

fn run_hook(home: &PathBuf, command: &str) -> String {
    let event = serde_json::json!({
        "hook_event_name": "PreToolUse",
        "session_id": "case-number-test",
        "timestamp": "2026-10-23T10:00:00Z",
        "tool_name": "Bash",
        "tool_input": { "command": command },
    });
    let mut child = Command::new(env!("CARGO_BIN_EXE_cop-hook"))
        .env_clear()
        .env("HOME", home)
        .env(
            "AGENTCOP_POLICY",
            concat!(env!("CARGO_MANIFEST_DIR"), "/../../policy/default.toml"),
        )
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
    let v: serde_json::Value = serde_json::from_slice(&out.stdout).expect("hook prints JSON");
    v["hookSpecificOutput"]["permissionDecisionReason"]
        .as_str()
        .unwrap()
        .to_string()
}

fn fresh_home(name: &str) -> PathBuf {
    let home = PathBuf::from(env!("CARGO_TARGET_TMPDIR"))
        .join(format!("case-{name}-{}", std::process::id()));
    let _ = fs::remove_dir_all(&home);
    fs::create_dir_all(home.join(".agentcop")).unwrap();
    fs::set_permissions(
        home.join(".agentcop"),
        std::os::unix::fs::PermissionsExt::from_mode(0o700),
    )
    .unwrap();
    home
}

/// The case ID in a reason, e.g. "[CASE-0123456789ab]".
fn case_id_in(reason: &str) -> String {
    let start = reason.find("CASE-").expect("reason must name a case");
    reason[start..start + 17].to_string()
}

#[test]
fn gate_a_block_names_a_case_that_exists_in_evidence() {
    let home = fresh_home("gate-a");
    let reason = run_hook(&home, "railway volume delete prod-db");
    let id = case_id_in(&reason);
    let store = EvidenceStore::new(&home.join(".agentcop/evidence.db")).unwrap();
    let rows = store.find_by_hash_prefix(&id[5..]).unwrap();
    assert_eq!(rows.len(), 1, "the named case must exist: {id}");
    assert_eq!(rows[0].verdict, "deny");
}

#[test]
fn allowed_calls_also_name_their_case() {
    let home = fresh_home("allow");
    let reason = run_hook(&home, "ls -la");
    assert!(case_id_in(&reason).starts_with("CASE-"));
}
