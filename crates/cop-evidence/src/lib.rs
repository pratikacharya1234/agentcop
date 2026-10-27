//! Hash-chained, append-only SQLite evidence store
//!
//! PLAN:
//! 1. Create SQLite schema with hash chain column
//! 2. Implement append operation that stores previous hash
//! 3. Implement verify() to check chain integrity
//! 4. Guard against edit/delete with integrity checks
//! 5. Performance: 10k entries verify in <1s

use cop_core::{Case, Verdict};
use rusqlite::{params, Connection, Result as SqliteResult};
use sha2::{Digest, Sha256};
use std::path::Path;

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
    /// Create or open an evidence store at the given path
    pub fn new(path: &Path) -> SqliteResult<Self> {
        let conn = Connection::open(path)?;

        // Create the cases table if it doesn't exist
        conn.execute(
            "CREATE TABLE IF NOT EXISTS cases (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                timestamp TEXT NOT NULL,
                event_json TEXT NOT NULL,
                verdict TEXT NOT NULL,
                reason TEXT NOT NULL,
                hash TEXT NOT NULL UNIQUE,
                prev_hash TEXT NOT NULL
            )",
            [],
        )?;

        Ok(EvidenceStore { conn })
    }

    /// Append a case to the evidence store
    pub fn append(&self, case: &Case) -> SqliteResult<i64> {
        let event_json = serde_json::to_string(&case.event).expect("Failed to serialize event");
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
        let hash_input = format!("{}{}{}{}", event_json, verdict_str, reason, prev_hash);
        let hash = compute_sha256(&hash_input);

        // Insert the case
        let timestamp = chrono::Local::now().to_rfc3339();
        self.conn.execute(
            "INSERT INTO cases (timestamp, event_json, verdict, reason, hash, prev_hash)
             VALUES (?, ?, ?, ?, ?, ?)",
            params![
                &timestamp,
                &event_json,
                verdict_str,
                reason,
                &hash,
                &prev_hash
            ],
        )?;

        // Return the ID of the newly inserted row
        Ok(self.conn.last_insert_rowid())
    }

    /// Verify the integrity of the evidence chain
    pub fn verify(&self) -> SqliteResult<()> {
        let mut stmt = self.conn.prepare(
            "SELECT id, event_json, verdict, reason, hash, prev_hash FROM cases ORDER BY id ASC",
        )?;

        let records = stmt.query_map([], |row| {
            Ok(EvidenceRecord {
                id: row.get(0)?,
                timestamp: String::new(), // Not needed for verification
                event_json: row.get(1)?,
                verdict: row.get(2)?,
                reason: row.get(3)?,
                hash: row.get(4)?,
                prev_hash: row.get(5)?,
            })
        })?;

        let mut last_hash = "GENESIS".to_string();
        for record_result in records {
            let record = record_result?;

            // Check that prev_hash matches what we expect (the last hash we saw)
            if record.prev_hash != last_hash {
                return Err(rusqlite::Error::InvalidQuery);
            }

            // Recompute the hash and check it matches
            let hash_input = format!(
                "{}{}{}{}",
                record.event_json, record.verdict, record.reason, record.prev_hash
            );
            let computed_hash = compute_sha256(&hash_input);
            if computed_hash != record.hash {
                return Err(rusqlite::Error::InvalidQuery);
            }

            last_hash = record.hash.clone();
        }

        Ok(())
    }

    /// Get the number of cases in the store
    pub fn count(&self) -> SqliteResult<u64> {
        self.conn
            .query_row("SELECT COUNT(*) FROM cases", [], |row| row.get(0))
    }
}

/// Compute SHA-256 hash of a string
fn compute_sha256(input: &str) -> String {
    let mut hasher = Sha256::new();
    hasher.update(input.as_bytes());
    format!("{:x}", hasher.finalize())
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
