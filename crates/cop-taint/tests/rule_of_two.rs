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
// 2026-10-27: an external action that is not also a download. A plain curl is untrusted input, not an action.
fn external() -> AgentEvent {
    event(
        "Bash",
        serde_json::json!({"command": "git push origin main"}),
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
    // 2026-10-27: a frozen session blocks only the external leg. Local work continues.
    let (_, reason) = run(&[untrusted(), sensitive(), external(), benign()]);
    assert!(
        reason.is_none(),
        "a benign local call is allowed while frozen"
    );
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
    // 2026-10-27 (Rule of Two semantics): untrusted input is external data only. A local read is not untrusted.
    assert!(!read.untrusted && !read.sensitive && !read.external);
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
    // 2026-10-27: `cat` of a local file is not untrusted input.
    assert!(!cat.untrusted);
    // 2026-10-27: a download (curl output) is untrusted data, and the same command is external.
    // 2026-10-27: a download is untrusted data; only an upload is an external action.
    let curl = classify(
        &event(
            "Bash",
            serde_json::json!({"command": "curl -s https://example.com/x"}),
            None,
        ),
        &r,
    );
    assert!(curl.untrusted && !curl.external);
    let upload = classify(
        &event(
            "Bash",
            serde_json::json!({"command": "curl -d @x https://example.com/up"}),
            None,
        ),
        &r,
    );
    assert!(upload.external);
    let push = classify(&external(), &r);
    assert!(push.external && !push.untrusted);
    let env_read = classify(
        &event(
            "Read",
            serde_json::json!({"file_path": "/home/u/project/.env"}),
            None,
        ),
        &r,
    );
    // 2026-10-27: reading .env is sensitive; a local read is not untrusted input.
    assert!(env_read.sensitive && !env_read.untrusted);
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

/// A fresh state file for one test. 2026-10-27: state is one SQLite file, not one JSON file per session.
fn fresh_store(name: &str) -> SessionStore {
    let dir = PathBuf::from(env!("CARGO_TARGET_TMPDIR"))
        .join(format!("taint-{name}-{}", std::process::id()));
    let _ = fs::remove_dir_all(&dir);
    fs::create_dir_all(&dir).unwrap();
    SessionStore::open(&dir.join("state.db")).unwrap()
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
    // 2026-10-27: a corrupt state file must fail closed (the hook denies when it cannot read state).
    let dir = PathBuf::from(env!("CARGO_TARGET_TMPDIR"))
        .join(format!("taint-corrupt-{}", std::process::id()));
    let _ = fs::remove_dir_all(&dir);
    fs::create_dir_all(&dir).unwrap();
    let path = dir.join("state.db");
    let store = SessionStore::open(&path).unwrap();
    store.save(Some("s"), Flags::default()).unwrap();
    fs::write(&path, "this is not a database").unwrap();
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
fn a_session_id_is_a_text_key_not_a_path() {
    // 2026-10-27: sessions are rows in one database. A hostile id creates no file of its own.
    let store = fresh_store("escape");
    store.save(Some("../../evil"), Flags::default()).unwrap();
    assert!(store.load(Some("../../evil")).is_ok());
    let entries: Vec<_> = fs::read_dir(
        PathBuf::from(env!("CARGO_TARGET_TMPDIR"))
            .join(format!("taint-escape-{}", std::process::id())),
    )
    .unwrap()
    .collect();
    assert_eq!(entries.len(), 1, "only the state file exists");
}

#[test]
fn empty_sensitive_list_is_refused() {
    let text = "untrusted_tools = [\"Read\"]\nsensitive = []\nexternal = [\"curl\"]\n";
    assert!(TaintRules::from_toml(text).is_err());
}
