//! Item 3 guards (2026-10-27), through the built cop-hook. Each case has its own temp HOME.
//!
//! PLAN:
//! 1. umask 0002: files are 0600, the folder 0700, and normal calls are allowed (no umask reliance).
//! 2. A group-writable state file is refused, and the refusal names the fix command.
//! 3. A legacy evidence.db is archived by the hook, and the new chain is anchored to it. No lockout.
//! 4. An archive that was moved by hand is linked the same way, without losing data.
//! 5. Every secret type is masked before storage; the HMAC of the original input matches the key; the chain verifies.
//! 6. An old-format policy (no [[redact]] tables) still allows normal calls and still masks.
//! 7. `redact = "off"` is the explicit switch: the hook warns and stores what it is given.

use cop_evidence::EvidenceStore;
use hmac::{Hmac, Mac};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use std::fs;
use std::io::Write;
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::sync::atomic::{AtomicUsize, Ordering};

static COUNTER: AtomicUsize = AtomicUsize::new(0);

const REPO_POLICY: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/../../policy/default.toml");

fn fresh_home(name: &str) -> PathBuf {
    let n = COUNTER.fetch_add(1, Ordering::SeqCst);
    let dir = PathBuf::from(env!("CARGO_TARGET_TMPDIR"))
        .join(format!("state-{name}-{}-{n}", std::process::id()));
    let _ = fs::remove_dir_all(&dir);
    fs::create_dir_all(&dir).unwrap();
    dir
}

/// Run the hook. `umask` (when given) is set by a shell in front of it, the way a user's login shell would.
fn run_hook(
    home: &Path,
    policy: &str,
    umask: Option<&str>,
    session: &str,
    tool: &str,
    input: Value,
) -> (String, String) {
    let event = json!({
        "hook_event_name": "PreToolUse",
        "session_id": session,
        "cwd": home,
        "timestamp": "2026-10-27T10:00:00Z",
        "tool_name": tool,
        "tool_input": input,
    });
    let bin = env!("CARGO_BIN_EXE_cop-hook");
    let mut cmd = match umask {
        Some(mask) => {
            let mut c = Command::new("sh");
            c.arg("-c")
                .arg(format!("umask {mask}; exec \"$0\""))
                .arg(bin);
            c
        }
        None => Command::new(bin),
    };
    let mut child = cmd
        .env_clear()
        .env("HOME", home)
        .env("AGENTCOP_POLICY", policy)
        .current_dir(home)
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
    let v: Value = serde_json::from_slice(&out.stdout).unwrap_or_else(|e| {
        panic!(
            "no JSON verdict ({e}): {}",
            String::from_utf8_lossy(&out.stderr)
        )
    });
    let body = &v["hookSpecificOutput"];
    (
        body["permissionDecision"]
            .as_str()
            .unwrap_or("")
            .to_string(),
        body["permissionDecisionReason"]
            .as_str()
            .unwrap_or("")
            .to_string(),
    )
}

fn bash(home: &Path, cmd: &str) -> (String, String) {
    run_hook(
        home,
        REPO_POLICY,
        None,
        "s",
        "Bash",
        json!({ "command": cmd }),
    )
}

fn mode(path: &Path) -> u32 {
    fs::metadata(path).unwrap().permissions().mode() & 0o777
}

fn state(home: &Path) -> PathBuf {
    home.join(".agentcop")
}

/// A state folder made the way AgentCop makes it: 0700, whatever the umask.
fn make_state_dir(home: &Path) {
    fs::create_dir_all(state(home)).unwrap();
    fs::set_permissions(state(home), fs::Permissions::from_mode(0o700)).unwrap();
}

// 1. umask.

#[test]
fn umask_0002_still_creates_private_files_and_folder_and_allows_normal_calls() {
    let home = fresh_home("umask");
    let (decision, reason) = run_hook(
        &home,
        REPO_POLICY,
        Some("0002"),
        "u1",
        "Bash",
        json!({ "command": "ls" }),
    );
    assert_eq!(decision, "allow", "{reason}");
    assert_eq!(mode(&state(&home)), 0o700, "the folder is 0700");
    for entry in fs::read_dir(state(&home)).unwrap() {
        let path = entry.unwrap().path();
        if path.is_file() {
            assert_eq!(mode(&path), 0o600, "{} must be 0600", path.display());
        }
    }
    assert_eq!(mode(&state(&home).join("hmac.key")), 0o600);
    assert_eq!(mode(&state(&home).join("state.db")), 0o600);
    assert_eq!(mode(&state(&home).join("evidence.db")), 0o600);
}

// 2. Refusal names the fix.

#[test]
fn group_writable_state_is_refused_and_the_reason_names_the_fix() {
    let home = fresh_home("refuse");
    run_hook(
        &home,
        REPO_POLICY,
        None,
        "r1",
        "Bash",
        json!({ "command": "ls" }),
    );
    fs::set_permissions(
        state(&home).join("evidence.db"),
        fs::Permissions::from_mode(0o664),
    )
    .unwrap();
    let (decision, reason) = run_hook(
        &home,
        REPO_POLICY,
        None,
        "r1",
        "Bash",
        json!({ "command": "ls" }),
    );
    assert_eq!(decision, "deny", "{reason}");
    assert!(
        reason.contains("chmod 600"),
        "the refusal must name the fix: {reason}"
    );
    assert!(reason.contains("evidence.db"), "{reason}");
}

// 3 and 4. Legacy archive.

/// A v1 store as the old code wrote it: raw commands, the old hash formula, no meta table.
fn write_legacy(path: &Path, commands: &[&str]) -> String {
    let conn = rusqlite::Connection::open(path).unwrap();
    conn.execute(
        "CREATE TABLE cases (id INTEGER PRIMARY KEY AUTOINCREMENT, timestamp TEXT NOT NULL, event_json TEXT NOT NULL,
         verdict TEXT NOT NULL, reason TEXT NOT NULL, hash TEXT NOT NULL UNIQUE, prev_hash TEXT NOT NULL)",
        [],
    )
    .unwrap();
    let mut prev = "GENESIS".to_string();
    for cmd in commands {
        let event = json!({"hook_event_name": "PreToolUse", "tool_name": "Bash", "tool_input": {"command": cmd}}).to_string();
        let hash = format!(
            "{:x}",
            Sha256::digest(format!("{event}allow{}{prev}", "legacy").as_bytes())
        );
        conn.execute(
            "INSERT INTO cases (timestamp, event_json, verdict, reason, hash, prev_hash) VALUES ('2026-10-20', ?1, 'allow', 'legacy', ?2, ?3)",
            [&event, &hash, &prev],
        )
        .unwrap();
        prev = hash;
    }
    prev
}

#[test]
fn legacy_evidence_is_archived_by_the_hook_and_the_new_chain_is_anchored() {
    let home = fresh_home("legacy");
    make_state_dir(&home);
    let final_hash = write_legacy(&state(&home).join("evidence.db"), &["cat notes.txt", "ls"]);
    let (decision, reason) = bash(&home, "ls -la");
    assert_eq!(
        decision, "allow",
        "a legacy store must not lock the user out: {reason}"
    );
    let archive = state(&home).join("evidence-legacy.db");
    assert!(archive.exists(), "the legacy store is archived");
    assert_eq!(mode(&archive), 0o600);
    let fresh = EvidenceStore::new(&state(&home).join("evidence.db")).expect("new chain opens");
    assert_eq!(
        fresh.anchor().unwrap().as_deref(),
        Some(final_hash.as_str()),
        "anchored to the legacy final hash"
    );
    fresh.verify().expect("the new chain verifies");
}

#[test]
fn an_archive_moved_by_hand_is_linked_without_losing_it() {
    let home = fresh_home("moved");
    make_state_dir(&home);
    let final_hash = write_legacy(&state(&home).join("evidence-legacy.db"), &["git status"]);
    fs::set_permissions(
        state(&home).join("evidence-legacy.db"),
        fs::Permissions::from_mode(0o600),
    )
    .unwrap();
    let (decision, reason) = bash(&home, "ls");
    assert_eq!(decision, "allow", "{reason}");
    let archive = EvidenceStore::open_existing(&state(&home).join("evidence-legacy.db")).unwrap();
    assert_eq!(archive.count().unwrap(), 1, "the archive keeps its row");
    let fresh = EvidenceStore::new(&state(&home).join("evidence.db")).unwrap();
    assert_eq!(
        fresh.anchor().unwrap().as_deref(),
        Some(final_hash.as_str())
    );
    fresh.verify().unwrap();
}

// 5. Redaction, HMAC, chain.

const SECRETS: &[(&str, &str)] = &[
    ("aws-access-key", "AKIAIOSFODNN7EXAMPLE"),
    ("github-token", "ghp_abcdefghijklmnopqrstuvwxyz0123456789"),
    (
        "github-fine-grained-token",
        "github_pat_11ABCDEFG0123456789_abcdefghijklmnopqrstuvwxyz",
    ),
    ("api-key-sk", "sk-abcdefghijklmnopqrstuvwx1234"),
    ("slack-token", "xoxb-1234567890-abcdefghij"),
    ("jwt", "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxIn0.c2lnbmF0dXJl"),
    (
        "private-key-block",
        "-----BEGIN RSA PRIVATE KEY-----\nMIIBOgIBAAJBAKabc123\n-----END RSA PRIVATE KEY-----",
    ),
    ("authorization-header", "Authorization: Basic dXNlcjpwYXNz"),
    ("bearer-token", "Bearer abcdefgh12345678"),
    ("password-or-token-value", "password=hunter2secret"),
    ("url-userinfo", "https://alice:s3cretpass@example.com/x"),
];

#[test]
fn every_secret_type_is_masked_before_storage() {
    let home = fresh_home("redact");
    for (name, secret) in SECRETS {
        run_hook(
            &home,
            REPO_POLICY,
            None,
            "x",
            "Bash",
            json!({ "command": format!("echo {secret}") }),
        );
        let _ = name;
    }
    let store = EvidenceStore::new(&state(&home).join("evidence.db")).unwrap();
    let rows = store.all_rows().unwrap();
    assert_eq!(rows.len(), SECRETS.len());
    for (name, secret) in SECRETS {
        for (event_json, _) in &rows {
            assert!(
                !event_json.contains(secret),
                "{name} stored raw: {event_json}"
            );
        }
        assert!(
            rows.iter()
                .any(|(e, _)| e.contains(&format!("[REDACTED:{name}]"))),
            "{name} must be stored as [REDACTED:{name}]"
        );
    }
}

#[test]
fn hmac_of_the_original_input_matches_the_key_and_the_chain_verifies() {
    let home = fresh_home("hmac");
    run_hook(
        &home,
        REPO_POLICY,
        None,
        "h",
        "Bash",
        json!({ "command": "ls -la" }),
    );
    let key = fs::read(state(&home).join("hmac.key")).unwrap();
    let mut mac = <Hmac<Sha256> as Mac>::new_from_slice(&key).unwrap();
    mac.update(br#"{"command":"ls -la"}"#);
    let expected: String = mac
        .finalize()
        .into_bytes()
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect();
    let store = EvidenceStore::new(&state(&home).join("evidence.db")).unwrap();
    let rows = store.all_rows().unwrap();
    assert_eq!(rows.len(), 1);
    assert_eq!(
        rows[0].1, expected,
        "stored HMAC must match the recomputed one"
    );
    assert_ne!(
        rows[0].1,
        format!("{:x}", Sha256::digest(br#"{"command":"ls -la"}"#)),
        "no plain hash of the raw input"
    );
    store.verify().expect("chain verifies");
}

// 6. Old-format policy and the explicit off switch.

#[test]
fn old_format_policy_allows_normal_calls_and_still_masks() {
    let home = fresh_home("oldpolicy");
    // The shipped default has no [[redact]] tables: the built-in list applies.
    let (decision, reason) = bash(&home, "echo ghp_abcdefghijklmnopqrstuvwxyz0123456789");
    assert_eq!(decision, "allow", "{reason}");
    let rows = EvidenceStore::new(&state(&home).join("evidence.db"))
        .unwrap()
        .all_rows()
        .unwrap();
    assert!(rows
        .iter()
        .all(|(e, _)| !e.contains("ghp_abcdefghijklmnopqrstuvwxyz0123456789")));
    assert!(rows
        .iter()
        .any(|(e, _)| e.contains("[REDACTED:github-token]")));
}

#[test]
fn redact_off_is_the_explicit_switch_and_warns() {
    let home = fresh_home("off");
    let policy_text = fs::read_to_string(REPO_POLICY).unwrap();
    let policy = home.join("policy-off.toml");
    fs::write(&policy, format!("redact = \"off\"\n{policy_text}")).unwrap();
    fs::set_permissions(&policy, std::os::unix::fs::PermissionsExt::from_mode(0o600)).unwrap();
    let out = {
        let event = json!({"hook_event_name":"PreToolUse","session_id":"o","tool_name":"Bash","tool_input":{"command":"echo ghp_abcdefghijklmnopqrstuvwxyz0123456789"}});
        let mut child = Command::new(env!("CARGO_BIN_EXE_cop-hook"))
            .env_clear()
            .env("HOME", &home)
            .env("AGENTCOP_POLICY", &policy)
            .current_dir(&home)
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
        child.wait_with_output().unwrap()
    };
    assert!(String::from_utf8_lossy(&out.stderr).contains("WARNING: redact = \"off\""));
    let rows = EvidenceStore::new(&state(&home).join("evidence.db"))
        .unwrap()
        .all_rows()
        .unwrap();
    assert!(rows
        .iter()
        .any(|(e, _)| e.contains("ghp_abcdefghijklmnopqrstuvwxyz0123456789")));
}
