//! `agentcop cases` filters (2026-10-26): --today, --since, --would-block, and `cases show <ID>`. Each case runs
//! the built agentcop in its own temp HOME with its own evidence store.
use cop_core::{AgentEvent, Case, Verdict};
use cop_evidence::EvidenceStore;
use std::collections::HashMap;
use std::fs;
use std::path::{Path, PathBuf};
use std::process::{Command, Output};

fn sandbox(name: &str) -> PathBuf {
    let dir = PathBuf::from(env!("CARGO_TARGET_TMPDIR"))
        .join(format!("cases-{name}-{}", std::process::id()));
    let _ = fs::remove_dir_all(&dir);
    fs::create_dir_all(dir.join(".agentcop")).unwrap();
    dir
}

fn append(store: &EvidenceStore, command: &str, verdict: Verdict, reason: &str) {
    let case = Case {
        event: AgentEvent {
            hook_event_name: "PreToolUse".to_string(),
            timestamp: String::new(),
            session_id: Some("sess-1".to_string()),
            user_id: None,
            tool_name: "Bash".to_string(),
            tool_input: serde_json::json!({ "command": command }),
            context: HashMap::new(),
        },
        verdict,
        evidence_hash: None,
        reason: Some(reason.to_string()),
    };
    store.append(&case).unwrap();
}

/// A store with three cases: an old allow, a log-only ask from today, and a plain ask from today.
fn seeded(name: &str) -> PathBuf {
    let home = sandbox(name);
    let path = home.join(".agentcop/evidence.db");
    let store = EvidenceStore::new(&path).unwrap();
    append(&store, "ls -la", Verdict::Allow, "No rules matched");
    append(
        &store,
        "echo logged",
        Verdict::Ask,
        "[log-only] Running code after the session read a secret",
    );
    append(
        &store,
        "echo enforced",
        Verdict::Deny,
        "Deleting from the root or the home directory",
    );
    // Make the first row old, so the date filters have something to exclude. The chain is not re-checked here.
    let conn = rusqlite::Connection::open(&path).unwrap();
    conn.execute(
        "UPDATE cases SET timestamp = '2020-01-02T10:00:00-06:00' WHERE id = 1",
        [],
    )
    .unwrap();
    home
}

fn agentcop(home: &Path, args: &[&str]) -> Output {
    Command::new(env!("CARGO_BIN_EXE_agentcop"))
        .args(args)
        .env_clear()
        .env("HOME", home)
        .current_dir(home)
        .output()
        .unwrap()
}

fn text(out: &Output) -> String {
    String::from_utf8_lossy(&out.stdout).to_string()
}

/// The case IDs printed by a listing, in order.
fn listed_ids(out: &Output) -> Vec<String> {
    text(out)
        .lines()
        .filter(|l| l.starts_with("CASE-"))
        .map(|l| l.split_whitespace().next().unwrap().to_string())
        .collect()
}

#[test]
fn plain_listing_shows_every_case() {
    let home = seeded("plain");
    let out = agentcop(&home, &["cases"]);
    assert!(out.status.success());
    assert!(text(&out).contains("Total cases: 3"), "{}", text(&out));
    assert_eq!(listed_ids(&out).len(), 3);
}

#[test]
fn would_block_lists_only_log_only_cases() {
    let home = seeded("wb");
    let out = agentcop(&home, &["cases", "--would-block"]);
    assert!(out.status.success());
    let ids = listed_ids(&out);
    assert_eq!(ids.len(), 1, "{}", text(&out));
    assert!(text(&out).contains("[log-only] Running code after the session read a secret"));
}

#[test]
fn today_drops_the_old_case() {
    let home = seeded("today");
    let out = agentcop(&home, &["cases", "--today"]);
    assert!(out.status.success());
    assert_eq!(listed_ids(&out).len(), 2, "{}", text(&out));
    assert!(!text(&out).contains("2020-01-02"), "{}", text(&out));
}

#[test]
fn since_keeps_cases_at_or_after_the_date() {
    let home = seeded("since");
    let all = agentcop(&home, &["cases", "--since", "2000-01-01"]);
    assert_eq!(listed_ids(&all).len(), 3, "{}", text(&all));
    let none = agentcop(&home, &["cases", "--since", "2999-01-01"]);
    assert!(listed_ids(&none).is_empty(), "{}", text(&none));
}

#[test]
fn since_accepts_a_full_timestamp() {
    let home = seeded("since-ts");
    let out = agentcop(&home, &["cases", "--since", "2020-01-02T12:00:00-06:00"]);
    assert!(out.status.success());
    assert_eq!(listed_ids(&out).len(), 2, "{}", text(&out));
}

#[test]
fn flags_combine() {
    let home = seeded("combo");
    let out = agentcop(&home, &["cases", "--today", "--would-block"]);
    assert_eq!(listed_ids(&out).len(), 1, "{}", text(&out));
}

#[test]
fn a_bad_since_value_is_an_error_not_an_empty_list() {
    let home = seeded("bad");
    let out = agentcop(&home, &["cases", "--since", "last tuesday"]);
    assert_eq!(out.status.code(), Some(1));
    assert!(String::from_utf8_lossy(&out.stderr).contains("--since"));
}

#[test]
fn show_prints_one_case_with_its_event_and_reason() {
    let home = seeded("show");
    let id = listed_ids(&agentcop(&home, &["cases", "--would-block"]))[0].clone();
    let out = agentcop(&home, &["cases", "show", &id]);
    assert!(
        out.status.success(),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
    let shown = text(&out);
    assert!(shown.contains(&id), "{shown}");
    assert!(shown.contains("ask"), "{shown}");
    assert!(
        shown.contains("echo logged"),
        "the redacted input is shown: {shown}"
    );
    assert!(shown.contains("sess-1"), "{shown}");
}

#[test]
fn show_accepts_the_id_without_the_prefix_and_rejects_unknown_ids() {
    let home = seeded("show-bad");
    let id = listed_ids(&agentcop(&home, &["cases"]))[0].clone();
    let bare = id.trim_start_matches("CASE-").to_string();
    assert!(agentcop(&home, &["cases", "show", &bare]).status.success());
    let unknown = agentcop(&home, &["cases", "show", "CASE-000000000000"]);
    assert_eq!(unknown.status.code(), Some(1));
    assert!(String::from_utf8_lossy(&unknown.stderr).contains("no case"));
    let not_hex = agentcop(&home, &["cases", "show", "CASE-zz"]);
    assert_eq!(not_hex.status.code(), Some(1));
}
