//! `agentcop cases` (2026-10-26): list, filter and show evidence cases. PLAN:
//! 1. The filters are plain functions over an EvidenceRecord, so they are testable without a store.
//! 2. --today keeps rows whose local date is today's local date.
//! 3. --since keeps rows at or after a time: a date (YYYY-MM-DD, local midnight) or an RFC 3339 timestamp.
//! 4. --would-block keeps rows the hook marked "[log-only] ": it would have stopped them, but log-only mode allowed.
//! 5. show finds the one row whose hash starts with the ID's hex part, and prints it. Stored input is already redacted.
//!
//! Edge cases: a row with an unreadable timestamp is dropped only when a time filter is set. A bad --since is an
//! error, never an empty list.

use chrono::{DateTime, FixedOffset, Local, NaiveDate, TimeZone};
use cop_evidence::{EvidenceRecord, EvidenceStore};
use std::path::Path;

/// The reason prefix the hook writes for a case that log-only mode did not enforce.
const LOG_ONLY_PREFIX: &str = "[log-only] ";

/// The filters from the command line. All unset means every case.
#[derive(Debug, Default)]
pub struct Filter {
    pub today: bool,
    pub since: Option<DateTime<FixedOffset>>,
    pub would_block: bool,
}

impl Filter {
    /// Build a filter from the flags. `since` is parsed here, so a bad value fails before any output.
    pub fn from_flags(today: bool, since: Option<&str>, would_block: bool) -> Result<Self, String> {
        let since = since.map(parse_since).transpose()?;
        Ok(Filter {
            today,
            since,
            would_block,
        })
    }
}

/// `--since` value: YYYY-MM-DD (local midnight) or a full RFC 3339 time.
pub fn parse_since(text: &str) -> Result<DateTime<FixedOffset>, String> {
    let bad = || format!("--since expects YYYY-MM-DD or an RFC 3339 time, got {text:?}");
    if let Ok(at) = DateTime::parse_from_rfc3339(text) {
        return Ok(at);
    }
    let date = NaiveDate::parse_from_str(text, "%Y-%m-%d").map_err(|_| bad())?;
    let midnight = date.and_hms_opt(0, 0, 0).ok_or_else(bad)?;
    let local = Local
        .from_local_datetime(&midnight)
        .earliest()
        .ok_or_else(bad)?;
    Ok(local.fixed_offset())
}

/// True when a row passes every set filter. `today` is the local date to compare with.
pub fn keep(row: &EvidenceRecord, filter: &Filter, today: NaiveDate) -> bool {
    if filter.would_block && !row.reason.starts_with(LOG_ONLY_PREFIX) {
        return false;
    }
    if !filter.today && filter.since.is_none() {
        return true;
    }
    let Ok(at) = DateTime::parse_from_rfc3339(&row.timestamp) else {
        return false;
    };
    if filter.today && at.with_timezone(&Local).date_naive() != today {
        return false;
    }
    !filter.since.is_some_and(|since| at < since)
}

/// The ID users type: CASE- plus the first 12 hex characters of the hash.
pub fn case_id(row: &EvidenceRecord) -> String {
    let id: String = row.hash.chars().take(12).collect();
    format!("CASE-{id}")
}

/// `agentcop cases`: one line per kept case.
pub fn list(home: &Path, filter: &Filter) -> Result<(), String> {
    let evidence_path = home.join(".agentcop/evidence.db");
    if !evidence_path.exists() {
        println!("No cases yet");
        return Ok(());
    }
    let store = EvidenceStore::new(&evidence_path)
        .map_err(|e| format!("Failed to open evidence store: {}", e))?;
    let rows = store
        .find_by_hash_prefix("")
        .map_err(|e| format!("Failed to list cases: {}", e))?;
    let today = Local::now().date_naive();
    let kept: Vec<&EvidenceRecord> = rows.iter().filter(|r| keep(r, filter, today)).collect();
    println!("Total cases: {}", kept.len());
    for row in kept {
        println!(
            "{}  {:<5}  {}  {}",
            case_id(row),
            row.verdict,
            row.timestamp,
            row.reason
        );
    }
    Ok(())
}

/// `agentcop cases show <ID>`: one case in full. Accepts the ID with or without the CASE- prefix.
pub fn show(home: &Path, id: &str) -> Result<(), String> {
    let hex = id.strip_prefix("CASE-").unwrap_or(id);
    let evidence_path = home.join(".agentcop/evidence.db");
    let store = EvidenceStore::new(&evidence_path)
        .map_err(|e| format!("Failed to open evidence store: {}", e))?;
    let rows = store
        .find_by_hash_prefix(hex)
        .map_err(|e| format!("Failed to look up {id}: {}", e))?;
    match rows.as_slice() {
        [] => Err(format!("no case {id}")),
        [row] => {
            print!("{}", describe(row));
            Ok(())
        }
        _ => Err(format!(
            "{id} matches more than one case; use more characters"
        )),
    }
}

/// The full view of one case: the stored event (already redacted), the verdict and the hash.
pub fn describe(row: &EvidenceRecord) -> String {
    let event: serde_json::Value = serde_json::from_str(&row.event_json).unwrap_or_default();
    let text = |key: &str| event[key].as_str().unwrap_or("").to_string();
    let input = serde_json::to_string(&event["tool_input"]).unwrap_or_default();
    format!(
        "{}\n  when:    {}\n  verdict: {}\n  reason:  {}\n  tool:    {}\n  session: {}\n  input:   {}\n  hash:    {}\n",
        case_id(row),
        row.timestamp,
        row.verdict,
        row.reason,
        text("tool_name"),
        text("session_id"),
        input,
        row.hash
    )
}
