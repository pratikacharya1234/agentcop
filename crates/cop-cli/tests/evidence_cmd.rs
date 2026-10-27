//! `agentcop evidence purge-legacy` asks first; `agentcop verify` reports the anchor (2026-10-27).
use std::fs;
use std::io::Write;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};

fn home(name: &str) -> PathBuf {
    let dir = PathBuf::from(env!("CARGO_TARGET_TMPDIR"))
        .join(format!("evcmd-{name}-{}", std::process::id()));
    let _ = fs::remove_dir_all(&dir);
    fs::create_dir_all(dir.join(".agentcop")).unwrap();
    fs::set_permissions(
        dir.join(".agentcop"),
        std::os::unix::fs::PermissionsExt::from_mode(0o700),
    )
    .unwrap();
    dir
}

fn agentcop(home: &Path, args: &[&str], stdin: &str) -> (bool, String) {
    let mut child = Command::new(env!("CARGO_BIN_EXE_agentcop"))
        .args(args)
        .env_clear()
        .env("HOME", home)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    child
        .stdin
        .take()
        .unwrap()
        .write_all(stdin.as_bytes())
        .unwrap();
    let out = child.wait_with_output().unwrap();
    (
        out.status.success(),
        String::from_utf8_lossy(&out.stdout).to_string(),
    )
}

fn legacy_archive(home: &Path) {
    let path = home.join(".agentcop/evidence-legacy.db");
    let conn = rusqlite::Connection::open(&path).unwrap();
    conn.execute(
        "CREATE TABLE cases (id INTEGER PRIMARY KEY AUTOINCREMENT, timestamp TEXT NOT NULL, event_json TEXT NOT NULL,
         verdict TEXT NOT NULL, reason TEXT NOT NULL, hash TEXT NOT NULL UNIQUE, prev_hash TEXT NOT NULL)",
        [],
    )
    .unwrap();
    conn.execute(
        "INSERT INTO cases (timestamp, event_json, verdict, reason, hash, prev_hash) VALUES ('t', '{\"tool_input\":{\"command\":\"raw\"}}', 'allow', 'r', 'h1', 'GENESIS')",
        [],
    )
    .unwrap();
    fs::set_permissions(&path, std::os::unix::fs::PermissionsExt::from_mode(0o600)).ok();
}

#[test]
fn purge_legacy_keeps_the_archive_when_the_answer_is_no() {
    let h = home("purge-no");
    legacy_archive(&h);
    let (ok, out) = agentcop(&h, &["evidence", "purge-legacy"], "n\n");
    assert!(ok, "{out}");
    assert!(out.contains("Nothing deleted"), "{out}");
    assert!(h.join(".agentcop/evidence-legacy.db").exists());
}

#[test]
fn purge_legacy_deletes_after_a_yes() {
    let h = home("purge-yes");
    legacy_archive(&h);
    let (ok, out) = agentcop(&h, &["evidence", "purge-legacy"], "y\n");
    assert!(ok, "{out}");
    assert!(!h.join(".agentcop/evidence-legacy.db").exists());
}

#[test]
fn verify_reports_the_anchor_of_the_archived_chain() {
    let h = home("verify");
    legacy_archive(&h);
    // The hook (through archive-legacy) starts a chain anchored to the archive.
    let (ok, out) = agentcop(&h, &["evidence", "archive-legacy"], "");
    assert!(ok, "{out}");
    let (ok, out) = agentcop(&h, &["verify"], "");
    assert!(ok, "{out}");
    assert!(out.contains("anchor matches the archive: yes"), "{out}");
}
