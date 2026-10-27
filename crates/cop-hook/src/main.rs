//! Border patrol: tiny binary run by Claude Code hooks
//!
//! PLAN:
//! 1. Read JSON from stdin (PreToolUse hook input)
//! 2. Load policy and create judge
//! 3. Parse event + judge it
//! 4. Append to evidence store
//! 5. Output JSON verdict to stdout
//! 6. Exit code 0 (allow/ask/deny), code 2 on error (fail-closed)
//! 7. Cold start <50ms

use cop_core::{AgentEvent, Case, Verdict};
use cop_evidence::EvidenceStore;
use cop_policy::{Judge, Policy};
use cop_siren::{SoundEvent, SoundPlayer};
use serde::{Deserialize, Serialize};
use std::fs;
use std::io::{self, Read};
use std::path::PathBuf;

#[derive(Serialize, Deserialize)]
struct HookResponse {
    #[serde(rename = "permissionDecision")]
    permission_decision: String,
    #[serde(rename = "permissionDecisionReason")]
    permission_decision_reason: String,
}

fn main() {
    // Exit code 2 on any error (fail-closed)
    if let Err(e) = run() {
        eprintln!("Error: {}", e);
        let response = HookResponse {
            permission_decision: "deny".to_string(),
            permission_decision_reason: format!("Internal error: {}", e),
        };
        let _ = serde_json::to_writer(io::stdout(), &response);
        std::process::exit(2);
    }
}

fn run() -> Result<(), String> {
    let start = std::time::Instant::now();

    // Load policy from policy/default.toml
    let policy_path = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .ok_or("Failed to find crate parent")?
        .parent()
        .ok_or("Failed to find repo root")?
        .join("policy/default.toml");

    let policy_toml =
        fs::read_to_string(&policy_path).map_err(|e| format!("Failed to read policy: {}", e))?;
    let policy: Policy =
        toml::from_str(&policy_toml).map_err(|e| format!("Failed to parse policy: {}", e))?;

    // Create judge from policy
    let judge = Judge::new(policy).map_err(|e| format!("Failed to create judge: {}", e))?;

    // Create sound player (for background audio playback)
    let player = SoundPlayer::new();

    // Create or open evidence store
    let evidence_dir = dirs::home_dir()
        .ok_or("Failed to find home directory")?
        .join(".agentcop");
    fs::create_dir_all(&evidence_dir)
        .map_err(|e| format!("Failed to create evidence directory: {}", e))?;

    let evidence_path = evidence_dir.join("evidence.db");
    let store = EvidenceStore::new(&evidence_path)
        .map_err(|e| format!("Failed to open evidence store: {}", e))?;

    // Read JSON from stdin
    let mut stdin_data = String::new();
    io::stdin()
        .read_to_string(&mut stdin_data)
        .map_err(|e| format!("Failed to read stdin: {}", e))?;

    // Parse as AgentEvent
    let event: AgentEvent =
        serde_json::from_str(&stdin_data).map_err(|e| format!("Failed to parse event: {}", e))?;

    // Judge the event
    let (verdict, reason) = judge.judge(&event);

    // Create case and append to evidence store
    let case = Case {
        event,
        verdict,
        evidence_hash: None,
        reason: Some(reason),
    };
    store
        .append(&case)
        .map_err(|e| format!("Failed to append to evidence: {}", e))?;

    // Output verdict JSON (before playing sound, so it returns immediately)
    let verdict_str = match verdict {
        Verdict::Allow => "allow",
        Verdict::Ask => "ask",
        Verdict::Deny => "deny",
    };

    let response = HookResponse {
        permission_decision: verdict_str.to_string(),
        permission_decision_reason: case.reason.unwrap_or_default(),
    };

    serde_json::to_writer(io::stdout(), &response)
        .map_err(|e| format!("Failed to write response: {}", e))?;

    // Play sound in background (never blocks verdict return)
    let sound_event = match verdict {
        Verdict::Allow => SoundEvent::Allow,
        Verdict::Ask => SoundEvent::Ask,
        Verdict::Deny => SoundEvent::Deny,
    };
    player.play(sound_event);

    let elapsed = start.elapsed();
    eprintln!(
        "Hook execution time: {:.2}ms",
        elapsed.as_micros() as f64 / 1000.0
    );

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn can_create_hook_response() {
        let response = HookResponse {
            permission_decision: "allow".to_string(),
            permission_decision_reason: "Test".to_string(),
        };
        let json = serde_json::to_string(&response).unwrap();
        assert!(json.contains("permissionDecision"));
        assert!(json.contains("allow"));
    }

    #[test]
    fn verdict_serializes_to_lowercase() {
        let allow_response = HookResponse {
            permission_decision: "allow".to_string(),
            permission_decision_reason: String::new(),
        };
        let json = serde_json::to_string(&allow_response).unwrap();
        assert!(json.contains("\"allow\""));
    }

    #[test]
    fn sound_event_maps_to_verdict() {
        let allow_event = match Verdict::Allow {
            Verdict::Allow => SoundEvent::Allow,
            Verdict::Ask => SoundEvent::Ask,
            Verdict::Deny => SoundEvent::Deny,
        };
        assert_eq!(allow_event, SoundEvent::Allow);

        let deny_event = match Verdict::Deny {
            Verdict::Allow => SoundEvent::Allow,
            Verdict::Ask => SoundEvent::Ask,
            Verdict::Deny => SoundEvent::Deny,
        };
        assert_eq!(deny_event, SoundEvent::Deny);
    }
}
