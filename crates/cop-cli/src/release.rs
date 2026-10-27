//! `agentcop release <session>`: end a Rule of Two freeze. A person decides, and the release is logged.
//!
//! PLAN:
//! 1. Load the session. If it is not frozen, say so and stop.
//! 2. Show the trigger, its evidence record, and how many external calls were blocked.
//! 3. Ask for confirmation. Anything other than "y" or "yes" changes nothing.
//! 4. Clear the freeze (cop_taint::release) and append a release row to the evidence store: who and when.

use cop_core::{AgentEvent, Case, Verdict};
use cop_evidence::EvidenceStore;
use cop_taint::SessionStore;
use std::collections::HashMap;
use std::io::{self, BufRead, Write};
use std::time::{SystemTime, UNIX_EPOCH};

pub fn run(session: &str) -> Result<(), String> {
    let state_dir = dirs::home_dir()
        .ok_or("Failed to find home directory")?
        .join(".agentcop");
    let sessions = SessionStore {
        dir: state_dir.join("sessions"),
    };
    let flags = sessions.load(Some(session))?;
    if !flags.frozen {
        println!("Session {session} is not frozen. Nothing to release.");
        return Ok(());
    }
    let freeze = flags.freeze.unwrap_or_default();
    println!("Session {session} is frozen by Rule of Two.");
    println!("Trigger: {}", freeze.trigger);
    println!("Trigger record: {}", freeze.case);
    println!("External calls blocked so far: {}", freeze.blocked);
    print!("Release it? The next external action will be asked, not denied. [y/N] ");
    io::stdout().flush().map_err(|e| e.to_string())?;

    let mut answer = String::new();
    io::stdin()
        .lock()
        .read_line(&mut answer)
        .map_err(|e| format!("read answer: {e}"))?;
    if !matches!(answer.trim().to_lowercase().as_str(), "y" | "yes") {
        println!("Session {session} not released.");
        return Ok(());
    }

    let by = std::env::var("USER").unwrap_or_else(|_| "unknown".to_string());
    let at = format!(
        "unix:{}",
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0)
    );
    let released = cop_taint::release(&sessions, Some(session), &by, &at)?
        .ok_or("the session was not frozen")?;

    let evidence = EvidenceStore::new(&state_dir.join("evidence.db"))
        .map_err(|e| format!("Failed to open evidence store: {e}"))?;
    let case = Case {
        event: AgentEvent {
            hook_event_name: "Release".to_string(),
            timestamp: at.clone(),
            session_id: Some(session.to_string()),
            user_id: Some(by.clone()),
            tool_name: "agentcop release".to_string(),
            tool_input: serde_json::json!({
                "session": session,
                "trigger_case": released.case,
                "blocked": released.blocked,
            }),
            context: HashMap::new(),
        },
        verdict: Verdict::Allow,
        evidence_hash: None,
        reason: Some(format!(
            "Released by {by} at {at}; trigger {}; {} external calls blocked",
            released.case, released.blocked
        )),
    };
    let row = evidence
        .append(&case)
        .map_err(|e| format!("Failed to append release row: {e}"))?;
    let hash = evidence
        .hash_for(row)
        .map_err(|e| format!("Failed to read release hash: {e}"))?;
    println!(
        "Released session {session}. Release record: CASE-{}.",
        &hash[..12]
    );
    Ok(())
}
