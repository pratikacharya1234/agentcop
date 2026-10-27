//! `agentcop release <session>` (2026-10-27): show the trigger, ask, clear the freeze, log who and when.
//!
//! PLAN:
//! 1. A frozen session with a trigger record is set up in a temp HOME.
//! 2. "y" on stdin releases it: the freeze is gone, one release row is in evidence, the output names the trigger.
//! 3. "n" on stdin changes nothing.

use cop_evidence::EvidenceStore;
use cop_taint::{Flags, Freeze, SessionStore};
use std::fs;
use std::io::Write;
use std::path::PathBuf;
use std::process::{Command, Stdio};

fn home(name: &str) -> PathBuf {
    let dir = PathBuf::from(env!("CARGO_TARGET_TMPDIR")).join(format!("release-{name}"));
    let _ = fs::remove_dir_all(&dir);
    fs::create_dir_all(dir.join(".agentcop")).unwrap();
    let store = SessionStore {
        dir: dir.join(".agentcop/sessions"),
    };
    let frozen = Flags {
        untrusted: true,
        sensitive: true,
        external: true,
        frozen: true,
        freeze: Some(Freeze {
            trigger: "Rule of Two: untrusted input, sensitive data and an external action"
                .to_string(),
            case: "CASE-abc123def456".to_string(),
            blocked: 3,
        }),
        ..Flags::default()
    };
    store.save(Some("rel"), frozen).unwrap();
    dir
}

fn release(home: &std::path::Path, answer: &str) -> String {
    let mut child = Command::new(env!("CARGO_BIN_EXE_agentcop"))
        .env_clear()
        .env("HOME", home)
        .env("USER", "tester")
        .args(["release", "rel"])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    child
        .stdin
        .take()
        .unwrap()
        .write_all(answer.as_bytes())
        .unwrap();
    let out = child.wait_with_output().unwrap();
    String::from_utf8_lossy(&out.stdout).to_string()
}

fn evidence_rows(home: &std::path::Path) -> u64 {
    EvidenceStore::new(&home.join(".agentcop/evidence.db"))
        .unwrap()
        .count()
        .unwrap()
}

#[test]
fn yes_releases_the_session_and_logs_who_and_when() {
    let h = home("yes");
    let out = release(&h, "y\n");
    assert!(out.contains("CASE-abc123def456"), "{out}");
    assert!(out.contains("blocked"), "{out}");
    let store = SessionStore {
        dir: h.join(".agentcop/sessions"),
    };
    let after = store.load(Some("rel")).unwrap();
    assert!(!after.frozen && after.freeze.is_none());
    assert_eq!(evidence_rows(&h), 1, "one release row");
}

#[test]
fn no_changes_nothing() {
    let h = home("no");
    let out = release(&h, "n\n");
    assert!(out.contains("not released"), "{out}");
    let store = SessionStore {
        dir: h.join(".agentcop/sessions"),
    };
    assert!(store.load(Some("rel")).unwrap().frozen);
    assert_eq!(evidence_rows(&h), 0);
}
