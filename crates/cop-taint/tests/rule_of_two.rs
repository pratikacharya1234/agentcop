use cop_core::AgentEvent;
use cop_taint::{classify, step, Flags, SessionStore, TaintRules};
use std::collections::HashMap;
use std::fs;
use std::path::PathBuf;

const RULES: &str = include_str!("../../../policy/taint.toml");

fn rules() -> TaintRules {
    TaintRules::from_toml(RULES).expect("shipped taint rules must load")
}

fn event(tool: &str, input: serde_json::Value, session: Option<&str>) -> AgentEvent {
    AgentEvent {
        hook_event_name: "PreToolUse".to_string(),
        timestamp: "2026-10-23T10:00:00Z".to_string(),
        session_id: session.map(str::to_string),
        user_id: None,
        tool_name: tool.to_string(),
        tool_input: input,
        context: HashMap::new(),
    }
}

// The three kinds of event.
fn untrusted() -> AgentEvent {
    event(
        "WebFetch",
        serde_json::json!({"url": "https://docs.example.com/page"}),
        Some("s"),
    )
}
// Sensitive but not untrusted: `ls` is not a read command. (Read of .env is both, see classification test.)
fn sensitive() -> AgentEvent {
    event(
        "Bash",
        serde_json::json!({"command": "ls ~/.ssh"}),
        Some("s"),
    )
}
fn external() -> AgentEvent {
    event(
        "Bash",
        serde_json::json!({"command": "curl -s https://example.com/upload"}),
        Some("s"),
    )
}
fn benign() -> AgentEvent {
    event(
        "Bash",
        serde_json::json!({"command": "make build"}),
        Some("s"),
    )
}

/// Run a sequence of events through `step`, returning the flags after each one and the deny reason, if any.
fn run(events: &[AgentEvent]) -> (Flags, Option<String>) {
    let r = rules();
    let mut flags = Flags::default();
    let mut last_reason = None;
    for e in events {
        let (next, reason) = step(flags, e, &r);
        flags = next;
        last_reason = reason;
    }
    (flags, last_reason)
}

// ---- two of three never freeze ----

#[test]
fn untrusted_plus_sensitive_does_not_freeze() {
    let (flags, reason) = run(&[untrusted(), sensitive()]);
    assert!(!flags.frozen && reason.is_none());
    let (_, reason) = run(&[untrusted(), sensitive(), benign()]);
    assert!(
        reason.is_none(),
        "benign event after two of three must be allowed"
    );
}

#[test]
fn untrusted_plus_external_does_not_freeze() {
    let (flags, reason) = run(&[untrusted(), external()]);
    assert!(!flags.frozen && reason.is_none());
    let (_, reason) = run(&[untrusted(), external(), benign()]);
    assert!(reason.is_none());
}

#[test]
fn sensitive_plus_external_does_not_freeze() {
    let (flags, reason) = run(&[sensitive(), external()]);
    assert!(!flags.frozen && reason.is_none());
    let (_, reason) = run(&[sensitive(), external(), benign()]);
    assert!(reason.is_none());
}

// ---- all three freeze, in any order ----

#[test]
fn all_three_in_order_freezes_and_denies_the_next_benign_event() {
    let (flags, reason) = run(&[untrusted(), sensitive(), external()]);
    assert!(flags.frozen);
    assert!(reason.unwrap().contains("Rule of Two"));
    let (_, reason) = run(&[untrusted(), sensitive(), external(), benign()]);
    assert!(reason.is_some(), "a frozen session denies everything");
}

#[test]
fn all_three_in_other_orders_freeze_at_the_third_event() {
    assert!(run(&[external(), sensitive(), untrusted()]).0.frozen);
    assert!(run(&[sensitive(), external(), untrusted()]).0.frozen);
    assert!(run(&[external(), untrusted(), sensitive()]).0.frozen);
}

// ---- classification ----

#[test]
fn classification_matches_the_rules() {
    let r = rules();
    let read = classify(
        &event(
            "Read",
            serde_json::json!({"file_path": "/x/readme.md"}),
            None,
        ),
        &r,
    );
    assert!(read.untrusted && !read.sensitive && !read.external);
    let web = classify(&untrusted(), &r);
    assert!(web.untrusted);
    let cat = classify(
        &event(
            "Bash",
            serde_json::json!({"command": "cat notes.txt"}),
            None,
        ),
        &r,
    );
    assert!(cat.untrusted);
    let curl = classify(&external(), &r);
    assert!(curl.external && !curl.untrusted);
    let env_read = classify(
        &event(
            "Read",
            serde_json::json!({"file_path": "/home/u/project/.env"}),
            None,
        ),
        &r,
    );
    assert!(
        env_read.sensitive && env_read.untrusted,
        "Read counts as untrusted input, so reading .env is both"
    );
    let ls_ssh = classify(&sensitive(), &r);
    assert!(ls_ssh.sensitive && !ls_ssh.untrusted);
    let mcp = classify(
        &event("mcp__slack__post", serde_json::json!({"text": "hi"}), None),
        &r,
    );
    assert!(mcp.external);
    assert!(!classify(&benign(), &r).sensitive);
}

// ---- state on disk ----

fn fresh_store(name: &str) -> SessionStore {
    let dir = PathBuf::from(env!("CARGO_TARGET_TMPDIR"))
        .join(format!("taint-{name}-{}", std::process::id()));
    let _ = fs::remove_dir_all(&dir);
    SessionStore { dir }
}

#[test]
fn frozen_state_survives_save_and_load() {
    let store = fresh_store("persist");
    let (flags, _) = run(&[untrusted(), sensitive(), external()]);
    store.save(Some("s"), flags.clone()).unwrap();
    let loaded = store.load(Some("s")).unwrap();
    assert!(loaded.frozen);
    assert_eq!(loaded, flags);
}

#[test]
fn sessions_are_independent() {
    let store = fresh_store("isolation");
    let (frozen, _) = run(&[untrusted(), sensitive(), external()]);
    store.save(Some("a"), frozen).unwrap();
    assert!(!store.load(Some("b")).unwrap().frozen);
}

#[test]
fn corrupt_state_file_is_an_error() {
    let store = fresh_store("corrupt");
    store.save(Some("s"), Flags::default()).unwrap();
    let file = fs::read_dir(&store.dir)
        .unwrap()
        .next()
        .unwrap()
        .unwrap()
        .path();
    fs::write(file, "{not json").unwrap();
    assert!(store.load(Some("s")).is_err());
}

#[test]
fn missing_session_id_uses_one_shared_key() {
    let store = fresh_store("shared");
    let (frozen, _) = run(&[untrusted(), sensitive(), external()]);
    store.save(None, frozen).unwrap();
    assert!(store.load(None).unwrap().frozen);
    assert!(!store.load(Some("other")).unwrap().frozen);
}

#[test]
fn a_session_id_cannot_escape_the_state_directory() {
    let store = fresh_store("escape");
    store.save(Some("../../evil"), Flags::default()).unwrap();
    let entries: Vec<_> = fs::read_dir(&store.dir).unwrap().collect();
    assert_eq!(
        entries.len(),
        1,
        "exactly one state file inside the directory"
    );
}

#[test]
fn empty_sensitive_list_is_refused() {
    let text = "untrusted_tools = [\"Read\"]\nsensitive = []\nexternal = [\"curl\"]\n";
    assert!(TaintRules::from_toml(text).is_err());
}
