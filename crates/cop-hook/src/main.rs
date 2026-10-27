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
use cop_policy::{Judge, Mode, Policy};
use cop_siren::{SoundEvent, SoundPlayer};
use cop_taint::{classify_with, step, SessionStore, TaintRules};
use serde::{Deserialize, Serialize};
use std::fs;
use std::io::{self, Read};
use std::path::PathBuf;

#[derive(Serialize, Deserialize)]
struct VerdictOutput {
    #[serde(rename = "hookEventName")]
    hook_event_name: String,
    #[serde(rename = "permissionDecision")]
    permission_decision: String,
    #[serde(rename = "permissionDecisionReason")]
    permission_decision_reason: String,
}

#[derive(Serialize, Deserialize)]
struct HookResponse {
    #[serde(rename = "hookSpecificOutput")]
    hook_specific_output: VerdictOutput,
}

fn main() {
    // Exit code 2 on any error (fail-closed)
    if let Err(e) = run() {
        eprintln!("Error: {}", e);
        let response = HookResponse {
            hook_specific_output: VerdictOutput {
                hook_event_name: "PreToolUse".to_string(),
                permission_decision: "deny".to_string(),
                permission_decision_reason: format!("Internal error: {}", e),
            },
        };
        let _ = serde_json::to_writer(io::stdout(), &response);
        std::process::exit(2);
    }
}

/// Taint rules: AGENTCOP_TAINT, then ~/.agentcop/taint.toml, then the copy compiled in.
fn load_taint_rules() -> Result<TaintRules, String> {
    const COMPILED: &str = include_str!("../../../policy/taint.toml");
    let text = match std::env::var_os("AGENTCOP_TAINT") {
        Some(path) => {
            fs::read_to_string(path).map_err(|e| format!("Failed to read taint rules: {}", e))?
        }
        None => match dirs::home_dir()
            .map(|h| h.join(".agentcop/taint.toml"))
            .filter(|p| p.exists())
        {
            Some(path) => fs::read_to_string(path)
                .map_err(|e| format!("Failed to read taint rules: {}", e))?,
            None => COMPILED.to_string(),
        },
    };
    TaintRules::from_toml(&text)
}

/// Resolve policy path at runtime from multiple sources
fn resolve_policy_path() -> Result<PathBuf, String> {
    // 1. Check AGENTCOP_POLICY environment variable
    if let Ok(path) = std::env::var("AGENTCOP_POLICY") {
        let policy_path = PathBuf::from(path);
        if policy_path.exists() {
            return Ok(policy_path);
        }
        return Err(format!(
            "AGENTCOP_POLICY points to non-existent file: {:?}",
            policy_path
        ));
    }

    // 2. Check ~/.agentcop/policy.toml
    if let Some(home) = dirs::home_dir() {
        let home_policy = home.join(".agentcop/policy.toml");
        if home_policy.exists() {
            return Ok(home_policy);
        }
    }

    // 3. Check ./policy/default.toml (for repo root execution)
    let cwd_policy = std::env::current_dir().ok().and_then(|cwd| {
        let path = cwd.join("policy/default.toml");
        if path.exists() {
            Some(path)
        } else {
            None
        }
    });

    if let Some(path) = cwd_policy {
        return Ok(path);
    }

    Err(
        "Policy file not found. Set AGENTCOP_POLICY env var or place policy.toml in ~/.agentcop/"
            .to_string(),
    )
}

fn run() -> Result<(), String> {
    let start = std::time::Instant::now();

    // Load policy from resolved path at runtime
    let policy_path = resolve_policy_path()?;

    let policy_toml =
        fs::read_to_string(&policy_path).map_err(|e| format!("Failed to read policy: {}", e))?;
    let policy: Policy =
        toml::from_str(&policy_toml).map_err(|e| format!("Failed to parse policy: {}", e))?;

    // Fail closed: a policy with no rules and no honeytokens would allow everything
    if policy.rules.is_empty() && policy.honeytokens.is_empty() {
        return Err(format!(
            "Policy {} loaded zero rules; refusing to allow everything",
            policy_path.display()
        ));
    }
    eprintln!(
        "Policy loaded: {} ({} rules, {} honeytokens)",
        policy_path.display(),
        policy.rules.len(),
        policy.honeytokens.len()
    );

    // Log-only: decisions are recorded, but the hook allows. Read before the policy moves into the judge.
    let log_only = policy.mode == Mode::LogOnly;

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

    // Parse as AgentEvent. Claude Code sends the working directory as `cwd`; it is kept in the context.
    let mut event: AgentEvent =
        serde_json::from_str(&stdin_data).map_err(|e| format!("Failed to parse event: {}", e))?;
    let raw: serde_json::Value = serde_json::from_str(&stdin_data).unwrap_or_default();
    if let Some(cwd) = raw["cwd"].as_str() {
        event.context.insert(
            "cwd".to_string(),
            serde_json::Value::String(cwd.to_string()),
        );
    }
    let hook_event_name = event.hook_event_name.clone();

    // Rule of Two: per-session state. The whole decision runs in one transaction on the state file,
    // so parallel hook processes see each other's freezes and counts. Any error here is a deny.
    let taint = load_taint_rules()?;
    let sessions = SessionStore::open(&evidence_dir.join("state.db"))?;
    let session_id = event.session_id.clone();
    let session = session_id.as_deref();
    let (verdict_out, reason_with_case) = sessions.update(session, |before| {
    let now = classify_with(&event, &taint, &before);
    let (mut after, trigger) = step(before.clone(), &event, &taint);

    // A frozen session blocks only external actions. Each block adds to the freeze's counter; it writes no row.
    let blocked_now = before.frozen && now.external;
    let (verdict, reason, record) = if blocked_now {
        let freeze = after.freeze.get_or_insert_with(Default::default);
        freeze.blocked += 1;
        let reason = format!(
            "Session frozen by Rule of Two (trigger {}). External action blocked; {} blocked so far. `agentcop release {}` ends the freeze.",
            freeze.case,
            freeze.blocked,
            session.unwrap_or("unknown")
        );
        (Verdict::Deny, reason, false)
    } else {
        let (verdict, reason) = match &trigger {
            // The event that completes the three properties: an external one is denied outright.
            Some(t) if now.external => (Verdict::Deny, t.clone()),
            Some(t) => {
                let (v, r) = judge.judge_in_session(&event, &before.written);
                (v, format!("{t}; {r}"))
            }
            None => judge.judge_in_session(&event, &before.written),
        };
        (verdict, reason, true)
    };

    // Log-only: the evidence keeps the real verdict, marked, and the output allows.
    let would_block = log_only && verdict != Verdict::Allow;
    let stored_reason = if would_block {
        format!("[log-only] {}", reason)
    } else {
        reason.clone()
    };
    let (verdict_out, reason_out) = if would_block {
        (
            Verdict::Allow,
            format!(
                "log-only, not enforced: would be {} ({})",
                verdict_word(verdict),
                reason
            ),
        )
    } else {
        (verdict, reason)
    };

    // One evidence row per judged call. A blocked frozen call adds none (the counter has it).
    let case_name = if record {
        let case = Case {
            event,
            verdict,
            evidence_hash: None,
            reason: Some(stored_reason),
        };
        let row_id = store
            .append(&case)
            .map_err(|e| format!("Failed to append to evidence: {}", e))?;
        let hash = store
            .hash_for(row_id)
            .map_err(|e| format!("Failed to read case hash: {}", e))?;
        let name = format!("CASE-{}", &hash[..12]);
        if trigger.is_some() {
            if let Some(freeze) = after.freeze.as_mut() {
                freeze.case = name.clone();
            }
        }
        name
    } else {
        after
            .freeze
            .as_ref()
            .map(|f| f.case.clone())
            .unwrap_or_default()
    };
    let reason_with_case = format!("{} [{}]", reason_out, case_name);
        Ok((after, (verdict_out, reason_with_case)))
    })?;

    // Output verdict JSON (before playing sound, so it returns immediately)
    let verdict_str = verdict_word(verdict_out);

    let response = HookResponse {
        hook_specific_output: VerdictOutput {
            hook_event_name: hook_event_name.clone(),
            permission_decision: verdict_str.to_string(),
            permission_decision_reason: reason_with_case,
        },
    };

    serde_json::to_writer(io::stdout(), &response)
        .map_err(|e| format!("Failed to write response: {}", e))?;

    // Play sound in background (never blocks verdict return)
    let sound_event = match verdict_out {
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

fn verdict_word(verdict: Verdict) -> &'static str {
    match verdict {
        Verdict::Allow => "allow",
        Verdict::Ask => "ask",
        Verdict::Deny => "deny",
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn can_create_hook_response() {
        let response = HookResponse {
            hook_specific_output: VerdictOutput {
                hook_event_name: "PreToolUse".to_string(),
                permission_decision: "allow".to_string(),
                permission_decision_reason: "Test".to_string(),
            },
        };
        let json = serde_json::to_string(&response).unwrap();
        assert!(json.contains("hookSpecificOutput"));
        assert!(json.contains("permissionDecision"));
        assert!(json.contains("allow"));
    }

    #[test]
    fn verdict_serializes_to_lowercase() {
        let allow_response = HookResponse {
            hook_specific_output: VerdictOutput {
                hook_event_name: "PreToolUse".to_string(),
                permission_decision: "allow".to_string(),
                permission_decision_reason: String::new(),
            },
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
