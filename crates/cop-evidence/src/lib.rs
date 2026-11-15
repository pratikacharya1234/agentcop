//! Hash-chained, append-only SQLite evidence store
//!
//! PLAN:
//! 1. Create SQLite schema with hash chain column
//! 2. Implement append operation that stores previous hash
//! 3. Implement verify() to check chain integrity
//! 4. Guard against edit/delete with integrity checks
//! 5. Performance: 10k entries verify in <1s

use cop_core::AgentEvent;
use cop_core::{Case, Verdict};
use rusqlite::{params, Connection, Result as SqliteResult};
use sha2::{Digest, Sha256};
use std::fs;
use std::path::{Path, PathBuf};
use std::time::Duration;

/// A case stored in the evidence database
#[derive(Debug, Clone)]
pub struct EvidenceRecord {
    pub id: u64,
    pub timestamp: String,
    pub event_json: String,
    pub verdict: String,
    pub reason: String,
    pub hash: String,
    pub prev_hash: String,
}

/// The evidence store: append-only, hash-chained SQLite database
pub struct EvidenceStore {
    conn: Connection,
}

impl EvidenceStore {
    /// Create or open an evidence store at the given path. A store in the legacy format (raw commands,
    /// no schema marker) is refused: archive it first with `agentcop evidence archive-legacy`.
    pub fn new(path: &Path) -> SqliteResult<Self> {
        if is_legacy(path) {
            return Err(rusqlite::Error::InvalidParameterName(
                LEGACY_MESSAGE.to_string(),
            ));
        }
        let conn = Connection::open(path)?;
        // Parallel hook processes wait for each other's append instead of failing.
        conn.busy_timeout(Duration::from_secs(10))?;
        // One transaction: another process must never see `cases` without `meta` (that shape is a legacy store).
        conn.execute_batch(
            "BEGIN IMMEDIATE;
             CREATE TABLE IF NOT EXISTS cases (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                timestamp TEXT NOT NULL,
                event_json TEXT NOT NULL,
                verdict TEXT NOT NULL,
                reason TEXT NOT NULL,
                input_hmac TEXT NOT NULL,
                hash TEXT NOT NULL UNIQUE,
                prev_hash TEXT NOT NULL
             );
             CREATE TABLE IF NOT EXISTS meta (key TEXT PRIMARY KEY, value TEXT NOT NULL);
             INSERT OR IGNORE INTO meta (key, value) VALUES ('schema', '2');
             COMMIT;",
        )?;
        cop_core::perms::secure_file(path).map_err(rusqlite::Error::InvalidParameterName)?;
        Ok(EvidenceStore { conn })
    }

    /// Open an existing store without the legacy check. Used to read an archive, never to append.
    pub fn open_existing(path: &Path) -> SqliteResult<Self> {
        Ok(EvidenceStore {
            conn: Connection::open(path)?,
        })
    }

    /// Append a case to the evidence store
    /// Append a case. The read of the previous hash and the insert run in one IMMEDIATE transaction,
    /// so parallel appends extend one chain instead of forking it.
    pub fn append(&self, case: &Case) -> SqliteResult<i64> {
        self.append_with_input(case, "")
    }

    /// Append a case with the HMAC of its original input (see `input_hmac`). The HMAC is part of the chain hash.
    pub fn append_with_input(&self, case: &Case, input_hmac: &str) -> SqliteResult<i64> {
        self.append_in_transaction(case, input_hmac, None)
    }

    /// Start a new chain after an archived one: the first row's prev_hash is the archived chain's final hash.
    /// Returns Ok(None) when the chain already has rows: a parallel process wrote the genesis first.
    pub fn start_after(
        &self,
        case: &Case,
        input_hmac: &str,
        archived_final_hash: &str,
    ) -> SqliteResult<Option<i64>> {
        self.conn.execute_batch("BEGIN IMMEDIATE")?;
        let rows: i64 = self
            .conn
            .query_row("SELECT COUNT(*) FROM cases", [], |row| row.get(0))?;
        if rows > 0 {
            self.conn.execute_batch("ROLLBACK")?;
            return Ok(None);
        }
        match self.append_chained(case, input_hmac, Some(archived_final_hash)) {
            Ok(id) => {
                self.conn.execute_batch("COMMIT")?;
                Ok(Some(id))
            }
            Err(e) => {
                let _ = self.conn.execute_batch("ROLLBACK");
                Err(e)
            }
        }
    }

    fn append_in_transaction(
        &self,
        case: &Case,
        input_hmac: &str,
        anchor: Option<&str>,
    ) -> SqliteResult<i64> {
        self.conn.execute_batch("BEGIN IMMEDIATE")?;
        match self.append_chained(case, input_hmac, anchor) {
            Ok(id) => {
                self.conn.execute_batch("COMMIT")?;
                Ok(id)
            }
            Err(e) => {
                let _ = self.conn.execute_batch("ROLLBACK");
                Err(e)
            }
        }
    }

    fn append_chained(
        &self,
        case: &Case,
        input_hmac: &str,
        anchor: Option<&str>,
    ) -> SqliteResult<i64> {
        // A serialization failure is an error, never a panic: the hook must fail closed, not crash.
        let event_json = serde_json::to_string(&case.event).map_err(|e| {
            rusqlite::Error::ToSqlConversionFailure(Box::new(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                format!("Failed to serialize event: {e}"),
            )))
        })?;
        let verdict_str = match case.verdict {
            Verdict::Allow => "allow",
            Verdict::Ask => "ask",
            Verdict::Deny => "deny",
        };
        let reason = case.reason.as_deref().unwrap_or("No reason provided");

        // Get the previous hash (last row in the database)
        let prev_hash: String = self
            .conn
            .query_row(
                "SELECT hash FROM cases ORDER BY id DESC LIMIT 1",
                [],
                |row| row.get(0),
            )
            .unwrap_or_else(|_| "GENESIS".to_string()); // First entry has GENESIS as prev

        // Compute the hash of (event_json + verdict + reason + prev_hash)
        let prev_hash = anchor.map(str::to_string).unwrap_or(prev_hash);
        let hash_input = format!(
            "{}{}{}{}{}",
            event_json, verdict_str, reason, input_hmac, prev_hash
        );
        let hash = compute_sha256(&hash_input);

        // Insert the case
        let timestamp = chrono::Local::now().to_rfc3339();
        self.conn.execute(
            "INSERT INTO cases (timestamp, event_json, verdict, reason, input_hmac, hash, prev_hash)
             VALUES (?, ?, ?, ?, ?, ?, ?)",
            params![
                &timestamp,
                &event_json,
                verdict_str,
                reason,
                input_hmac,
                &hash,
                &prev_hash
            ],
        )?;

        // Return the ID of the newly inserted row
        Ok(self.conn.last_insert_rowid())
    }

    /// Verify the integrity of the evidence chain. The first row links to "GENESIS", or, when this chain
    /// continues an archived one, to a Genesis row that names the archived chain's final hash.
    pub fn verify(&self) -> SqliteResult<()> {
        let mut stmt = self.conn.prepare(
            "SELECT id, event_json, verdict, reason, input_hmac, hash, prev_hash FROM cases ORDER BY id ASC",
        )?;
        let records = stmt.query_map([], |row| {
            Ok((
                row.get::<_, String>(1)?,
                row.get::<_, String>(2)?,
                row.get::<_, String>(3)?,
                row.get::<_, String>(4)?,
                row.get::<_, String>(5)?,
                row.get::<_, String>(6)?,
            ))
        })?;

        let mut last_hash = "GENESIS".to_string();
        let mut first = true;
        for record in records {
            let (event_json, verdict, reason, input_hmac, hash, prev_hash) = record?;
            if prev_hash != last_hash && !(first && is_genesis_row(&event_json)) {
                return Err(rusqlite::Error::InvalidQuery);
            }
            let hash_input = format!(
                "{}{}{}{}{}",
                event_json, verdict, reason, input_hmac, prev_hash
            );
            if compute_sha256(&hash_input) != hash {
                return Err(rusqlite::Error::InvalidQuery);
            }
            last_hash = hash;
            first = false;
        }
        Ok(())
    }

    /// The archived chain's final hash this chain continues from, if it was started by `start_after`.
    pub fn anchor(&self) -> SqliteResult<Option<String>> {
        let row: Option<(String, String)> = self
            .conn
            .query_row(
                "SELECT event_json, prev_hash FROM cases ORDER BY id ASC LIMIT 1",
                [],
                |row| Ok((row.get(0)?, row.get(1)?)),
            )
            .ok();
        Ok(match row {
            Some((event_json, prev)) if prev != "GENESIS" && is_genesis_row(&event_json) => {
                Some(prev)
            }
            _ => None,
        })
    }

    /// Get the number of cases in the store
    /// The hash of the row with this id. Used to name the case that was just appended.
    pub fn hash_for(&self, id: i64) -> SqliteResult<String> {
        self.conn
            .query_row("SELECT hash FROM cases WHERE id = ?1", params![id], |row| {
                row.get(0)
            })
    }

    /// Read-only lookup: rows whose hash starts with `prefix` (hex only), oldest first.
    pub fn find_by_hash_prefix(&self, prefix: &str) -> SqliteResult<Vec<EvidenceRecord>> {
        if !prefix.chars().all(|c| c.is_ascii_hexdigit()) {
            return Ok(Vec::new());
        }
        let mut stmt = self.conn.prepare(
            "SELECT id, timestamp, event_json, verdict, reason, hash, prev_hash
             FROM cases WHERE hash LIKE ?1 ORDER BY id",
        )?;
        let rows = stmt.query_map(params![format!("{prefix}%")], |row| {
            Ok(EvidenceRecord {
                id: row.get(0)?,
                timestamp: row.get(1)?,
                event_json: row.get(2)?,
                verdict: row.get(3)?,
                reason: row.get(4)?,
                hash: row.get(5)?,
                prev_hash: row.get(6)?,
            })
        })?;
        rows.collect()
    }

    /// Every row as (event_json, input_hmac), oldest first. For tests and migrations, not for display.
    pub fn all_rows(&self) -> SqliteResult<Vec<(String, String)>> {
        let mut stmt = self
            .conn
            .prepare("SELECT event_json, input_hmac FROM cases ORDER BY id ASC")?;
        let rows = stmt.query_map([], |row| Ok((row.get(0)?, row.get(1)?)))?;
        rows.collect()
    }

    pub fn count(&self) -> SqliteResult<u64> {
        self.conn
            .query_row("SELECT COUNT(*) FROM cases", [], |row| row.get(0))
    }
}

/// Shown when a legacy store is opened for appending.
pub const LEGACY_MESSAGE: &str =
    "legacy evidence store (raw commands, no schema marker); run `agentcop evidence archive-legacy`";

/// True for a store written before the redacted format: it has a cases table and no schema marker.
pub fn is_legacy(path: &Path) -> bool {
    if !path.exists() {
        return false;
    }
    let Ok(conn) = Connection::open(path) else {
        return false;
    };
    let has_cases: bool = conn
        .query_row(
            "SELECT COUNT(*) FROM sqlite_master WHERE type='table' AND name='cases'",
            [],
            |row| row.get::<_, i64>(0),
        )
        .map(|n| n > 0)
        .unwrap_or(false);
    let has_meta: bool = conn
        .query_row(
            "SELECT COUNT(*) FROM sqlite_master WHERE type='table' AND name='meta'",
            [],
            |row| row.get::<_, i64>(0),
        )
        .map(|n| n > 0)
        .unwrap_or(false);
    has_cases && !has_meta
}

/// The Genesis row a continued chain starts with (its event names the archive).
fn is_genesis_row(event_json: &str) -> bool {
    serde_json::from_str::<serde_json::Value>(event_json)
        .ok()
        .and_then(|v| v["hook_event_name"].as_str().map(|s| s == "Genesis"))
        .unwrap_or(false)
}

/// HMAC-SHA256 of the original input, as lowercase hex. The key is per install (see `load_or_create_hmac_key`).
/// The raw input is never stored or hashed without the key.
pub fn input_hmac(key: &[u8], original: &str) -> String {
    use hmac::{Hmac, Mac};
    // HMAC accepts a key of any length, so this cannot fail. If it ever did, the input is not
    // hashed: an empty digest is returned instead of a panic on the enforcement path.
    let Ok(mut mac) = <Hmac<Sha256> as Mac>::new_from_slice(key) else {
        return String::new();
    };
    mac.update(original.as_bytes());
    mac.finalize()
        .into_bytes()
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect()
}

/// Read the per-install HMAC key from `dir/hmac.key`, or create it: 32 random bytes, mode 0600.
pub fn load_or_create_hmac_key(dir: &Path) -> Result<Vec<u8>, String> {
    use std::io::{Read, Write};
    use std::os::unix::fs::OpenOptionsExt;
    let path = dir.join("hmac.key");
    if path.exists() {
        let key = fs::read(&path).map_err(|e| format!("read hmac key: {e}"))?;
        if key.len() < 32 {
            return Err("hmac.key is too short; refusing to run (fail closed)".to_string());
        }
        cop_core::perms::secure_file(&path)?;
        return Ok(key);
    }
    let mut key = vec![0u8; 32];
    fs::File::open("/dev/urandom")
        .and_then(|mut f| f.read_exact(&mut key))
        .map_err(|e| format!("read random bytes: {e}"))?;
    // Write the key to a private temp file, then hard-link it into place. The link fails if another process
    // created the key first, and then that key is read. Readers never see a partial key.
    let tmp = dir.join(format!(".hmac.key.{}.tmp", std::process::id()));
    let _ = fs::remove_file(&tmp);
    {
        let mut file = fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(&tmp)
            .map_err(|e| format!("create hmac key: {e}"))?;
        file.write_all(&key)
            .map_err(|e| format!("write hmac key: {e}"))?;
    }
    let linked = fs::hard_link(&tmp, &path);
    let _ = fs::remove_file(&tmp);
    match linked {
        Ok(()) => {
            cop_core::perms::secure_file(&path)?;
            Ok(key)
        }
        Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => {
            let existing = fs::read(&path).map_err(|e| format!("read hmac key: {e}"))?;
            if existing.len() < 32 {
                return Err("hmac.key is too short; refusing to run (fail closed)".to_string());
            }
            Ok(existing)
        }
        Err(e) => Err(format!("install hmac key: {e}")),
    }
}

/// Compute SHA-256 hash of a string
fn compute_sha256(input: &str) -> String {
    let mut hasher = Sha256::new();
    hasher.update(input.as_bytes());
    format!("{:x}", hasher.finalize())
}

/// Open the evidence chain in a state directory, archiving older evidence first (2026-10-27). Never a lockout.
///
/// 1. A legacy `evidence.db` (raw commands, no schema marker) is moved aside with its -wal, -shm and -journal
///    to `evidence-legacy.db` (or `evidence-legacy-N.db`), mode 0600.
/// 2. If an archive exists, the current chain must continue from its final hash. A chain that does not is moved
///    aside to `evidence-interim-<unix>.db` (its own chain stays valid), and a new chain starts.
/// 3. A new chain that continues an archive begins with one Genesis row, which names the archive and its
///    final hash. The archive itself is never changed.
///
/// Returns the open store, and a note for each thing that was done.
pub fn open_chain(dir: &Path) -> Result<(EvidenceStore, Vec<String>), String> {
    let mut notes = Vec::new();
    let evidence = dir.join("evidence.db");
    if is_legacy(&evidence) {
        let archive = next_free(dir, "evidence-legacy");
        move_aside(&evidence, &archive)?;
        notes.push(format!(
            "archived legacy evidence (raw commands) to {}",
            archive.display()
        ));
    }
    let Some(archive) = latest_archive(dir) else {
        let store =
            EvidenceStore::new(&evidence).map_err(|e| format!("open evidence store: {e}"))?;
        return Ok((store, notes));
    };
    let archived_final = final_hash(&archive)?;
    let archived_rows = EvidenceStore::open_existing(&archive)
        .and_then(|a| a.count())
        .map_err(|e| format!("read archive: {e}"))?;
    if evidence.exists() {
        let current = EvidenceStore::open_existing(&evidence)
            .map_err(|e| format!("open evidence store: {e}"))?;
        let anchored = current.anchor().map_err(|e| format!("read anchor: {e}"))?;
        drop(current);
        if anchored.as_deref() != Some(archived_final.as_str()) {
            let interim = next_free_stamped(dir, "evidence-interim");
            move_aside(&evidence, &interim)?;
            notes.push(format!(
                "moved an unanchored evidence chain to {} (it stays valid on its own)",
                interim.display()
            ));
        }
    }
    let store = EvidenceStore::new(&evidence).map_err(|e| format!("open evidence store: {e}"))?;
    let rows: u64 = store.count().map_err(|e| format!("count: {e}"))?;
    if rows == 0 {
        let genesis = Case {
            event: AgentEvent {
                hook_event_name: "Genesis".to_string(),
                timestamp: chrono::Local::now().to_rfc3339(),
                session_id: None,
                user_id: None,
                tool_name: "agentcop evidence".to_string(),
                tool_input: serde_json::json!({
                    "archive": archive.file_name().map(|n| n.to_string_lossy().into_owned()),
                    "archived_final_hash": archived_final,
                    "archived_rows": archived_rows,
                }),
                context: Default::default(),
            },
            verdict: Verdict::Allow,
            evidence_hash: None,
            reason: Some(format!(
                "Chain continues from archived evidence {}. The archive is unchanged.",
                archive.display()
            )),
        };
        let written = store
            .start_after(&genesis, "", &archived_final)
            .map_err(|e| format!("write genesis row: {e}"))?;
        if written.is_some() {
            notes.push(format!("new chain anchored to {}", archive.display()));
        }
    }
    Ok((store, notes))
}

/// The final hash of a chain file ("GENESIS" when it has no rows).
pub fn final_hash(path: &Path) -> Result<String, String> {
    let conn = Connection::open(path).map_err(|e| format!("open {}: {e}", path.display()))?;
    let hash: Option<String> = conn
        .query_row(
            "SELECT hash FROM cases ORDER BY id DESC LIMIT 1",
            [],
            |row| row.get(0),
        )
        .ok();
    Ok(hash.unwrap_or_else(|| "GENESIS".to_string()))
}

/// The newest archive: `evidence-legacy.db`, or the highest `evidence-legacy-N.db` that exists.
pub fn latest_archive(dir: &Path) -> Option<PathBuf> {
    let mut found = None;
    if dir.join("evidence-legacy.db").exists() {
        found = Some(dir.join("evidence-legacy.db"));
    }
    for n in 2..100 {
        let candidate = dir.join(format!("evidence-legacy-{n}.db"));
        if candidate.exists() {
            found = Some(candidate);
        }
    }
    found
}

/// The first free `<stem>.db`, `<stem>-2.db`, ...
fn next_free(dir: &Path, stem: &str) -> PathBuf {
    let first = dir.join(format!("{stem}.db"));
    if !first.exists() {
        return first;
    }
    (2..)
        .map(|n| dir.join(format!("{stem}-{n}.db")))
        .find(|p| !p.exists())
        .unwrap()
}

fn next_free_stamped(dir: &Path, stem: &str) -> PathBuf {
    let stamp = chrono::Local::now().format("%Y%m%d-%H%M%S");
    next_free(dir, &format!("{stem}-{stamp}"))
}

/// Rename a database and its companion files, then set the moved files to 0600.
fn move_aside(from: &Path, to: &Path) -> Result<(), String> {
    fs::rename(from, to).map_err(|e| format!("move {} aside: {e}", from.display()))?;
    cop_core::perms::secure_file(to)?;
    for suffix in ["-wal", "-shm", "-journal"] {
        let from_c = PathBuf::from(format!("{}{suffix}", from.display()));
        if from_c.exists() {
            let to_c = PathBuf::from(format!("{}{suffix}", to.display()));
            fs::rename(&from_c, &to_c).map_err(|e| format!("move {}: {e}", from_c.display()))?;
            cop_core::perms::secure_file(&to_c)?;
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use cop_core::AgentEvent;
    use serde_json::json;
    use tempfile::NamedTempFile;

    fn create_test_store() -> (EvidenceStore, NamedTempFile) {
        let temp = NamedTempFile::new().expect("Failed to create temp file");
        let path = temp.path().to_path_buf();
        let store = EvidenceStore::new(&path).expect("Failed to create store");
        (store, temp)
    }

    fn create_test_case(verdict: Verdict, reason: &str) -> Case {
        Case {
            event: AgentEvent {
                hook_event_name: "PreToolUse".to_string(),
                timestamp: "2026-10-20T00:00:00Z".to_string(),
                session_id: None,
                user_id: None,
                tool_name: "bash".to_string(),
                tool_input: json!({"command": "echo hello"}),
                context: Default::default(),
            },
            verdict,
            evidence_hash: None,
            reason: Some(reason.to_string()),
        }
    }

    #[test]
    fn append_and_verify() {
        let (store, _temp) = create_test_store();
        let case = create_test_case(Verdict::Allow, "Test case");

        let id = store.append(&case).expect("Failed to append case");
        assert_eq!(id, 1);

        store.verify().expect("Verify failed");
    }

    #[test]
    fn append_multiple_and_verify() {
        let (store, _temp) = create_test_store();

        for i in 0..10 {
            let case = create_test_case(Verdict::Allow, &format!("Case {}", i));
            store.append(&case).expect("Failed to append");
        }

        let count = store.count().expect("Failed to count");
        assert_eq!(count, 10);

        store.verify().expect("Verify failed");
    }

    #[test]
    fn verify_fails_if_hash_tampered() {
        let (store, _temp) = create_test_store();
        let case = create_test_case(Verdict::Deny, "Test");
        store.append(&case).expect("Failed to append");

        // Tamper with the hash
        store
            .conn
            .execute("UPDATE cases SET hash = 'fake_hash_value' WHERE id = 1", [])
            .expect("Failed to update");

        let result = store.verify();
        assert!(result.is_err(), "Verify should fail on tampered hash");
    }

    #[test]
    fn verify_fails_if_prev_hash_broken() {
        let (store, _temp) = create_test_store();
        let case1 = create_test_case(Verdict::Allow, "Case 1");
        let case2 = create_test_case(Verdict::Deny, "Case 2");

        store.append(&case1).expect("Failed to append case 1");
        store.append(&case2).expect("Failed to append case 2");

        // Break the chain by changing prev_hash of row 2
        store
            .conn
            .execute(
                "UPDATE cases SET prev_hash = 'broken_chain' WHERE id = 2",
                [],
            )
            .expect("Failed to update");

        let result = store.verify();
        assert!(result.is_err(), "Verify should fail on broken chain");
    }

    #[test]
    fn different_verdicts_produce_different_hashes() {
        let (_store, _temp) = create_test_store();

        let case_allow = Case {
            event: AgentEvent {
                hook_event_name: "PreToolUse".to_string(),
                timestamp: "2026-10-20T00:00:00Z".to_string(),
                session_id: None,
                user_id: None,
                tool_name: "bash".to_string(),
                tool_input: json!({"command": "test"}),
                context: Default::default(),
            },
            verdict: Verdict::Allow,
            evidence_hash: None,
            reason: Some("Allow".to_string()),
        };

        let _case_deny = Case {
            verdict: Verdict::Deny,
            ..case_allow.clone()
        };

        let hash1 = compute_sha256("testallowAllowtestGENESIS");
        let hash2 = compute_sha256("testdenyDenytestGENESIS");

        assert_ne!(
            hash1, hash2,
            "Different verdicts should have different hashes"
        );
    }

    #[test]
    fn benchmark_10k_appends_and_verify() {
        let (store, _temp) = create_test_store();

        let start = std::time::Instant::now();

        // Append 10,000 cases (appending speed is secondary, verification is the main test)
        for i in 0..10_000 {
            let case = create_test_case(
                if i % 3 == 0 {
                    Verdict::Deny
                } else if i % 3 == 1 {
                    Verdict::Ask
                } else {
                    Verdict::Allow
                },
                &format!("Case {}", i),
            );
            let _ = store.append(&case);
        }

        let append_time = start.elapsed();

        // Verify the chain (this must be under 1 second per spec)
        let verify_start = std::time::Instant::now();
        store.verify().expect("Verify failed");
        let verify_time = verify_start.elapsed();

        println!(
            "Appended 10k cases in {:?} ({:.2} ms/case)",
            append_time,
            append_time.as_micros() as f64 / 10_000.0 / 1000.0
        );
        println!(
            "Verified 10k cases in {:?} ({:.2} ms/case)",
            verify_time,
            verify_time.as_micros() as f64 / 10_000.0 / 1000.0
        );

        // Verify must complete in under 1 second per spec
        assert!(
            verify_time.as_secs() < 1,
            "Verification time exceeded 1 second: {:?}",
            verify_time
        );
    }
}
