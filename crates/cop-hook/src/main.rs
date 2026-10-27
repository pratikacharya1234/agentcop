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

use cop_core::redact::Redactor;
use cop_core::{AgentEvent, Case, Verdict};
use cop_policy::{
    choose_policy, Judge, Mode, Policy, PolicySource, LASTGOOD_FILE, LASTGOOD_HASH_FILE,
};
use cop_siren::{SoundEvent, SoundPlayer};
use cop_taint::{classify_with, step, SessionStore, TaintRules};
use serde::{Deserialize, Serialize};
use std::fs;
use std::io::{self, Read, Write};
use std::os::unix::fs::OpenOptionsExt;
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
    // `cop-hook --version` (2026-10-27): the doctor compares it with the CLI. It never reads stdin.
    if std::env::args().nth(1).as_deref() == Some("--version") {
        println!("cop-hook {}", env!("CARGO_PKG_VERSION"));
        return;
    }
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

    // The state directory and its files must not be writable by others (item 3). Refuse otherwise.
    let state_dir = dirs::home_dir()
        .ok_or("Failed to find home directory")?
        .join(".agentcop");
    if !state_dir.exists() {
        cop_core::perms::ensure_private_dir(&state_dir)?;
    }
    cop_core::perms::check_not_group_or_world_writable(&[
        state_dir.clone(),
        state_dir.join("evidence.db"),
        state_dir.join("state.db"),
        state_dir.join("hmac.key"),
        state_dir.join("policy.toml"),
    ])?;

    // Load policy from resolved path at runtime
    let policy_path = resolve_policy_path()?;

    let live_text =
        fs::read_to_string(&policy_path).map_err(|e| format!("Failed to read policy: {}", e))?;
    let policy_hash = sha256_hex(&live_text);

    // Fail closed: a live policy with no rules and no honeytokens would allow everything. That is an error,
    // not a fallback: the live file is broken and the user must see it.
    let live: Policy =
        toml::from_str(&live_text).map_err(|e| format!("Failed to parse policy: {}", e))?;
    if live.rules.is_empty() && live.honeytokens.is_empty() {
        return Err(format!(
            "Policy {} loaded zero rules; refusing to allow everything",
            policy_path.display()
        ));
    }

    // Item 4b: the live policy runs only while it passes the canaries. Otherwise last-known-good, then defaults.
    let lastgood = fs::read_to_string(state_dir.join(LASTGOOD_FILE)).ok();
    let chosen = choose_policy(&live_text, lastgood.as_deref())?;
    let policy: Policy =
        toml::from_str(&chosen.text).map_err(|e| format!("Failed to parse policy: {}", e))?;
    eprintln!(
        "Policy loaded: {} ({} rules, {} honeytokens)",
        policy_path.display(),
        policy.rules.len(),
        policy.honeytokens.len()
    );

    // Log-only: decisions are recorded, but the hook allows. Read before the policy moves into the judge.
    let log_only = policy.mode == Mode::LogOnly;

    // Redaction before storage (item 3). Without patterns, nothing could be masked: refuse.
    // Built-in patterns always apply; `redact = "off"` removes them, loudly.
    let redactor = match policy.redact_patterns()? {
        Some(rules) => Redactor::new(&rules)?,
        None => {
            eprintln!(
                "WARNING: redact = \"off\": secrets will be stored unmasked in the evidence store"
            );
            Redactor::new(&[])?
        }
    };

    // Create judge from policy
    let judge = Judge::new(policy).map_err(|e| format!("Failed to create judge: {}", e))?;

    // Create sound player (for background audio playback)
    let player = SoundPlayer::new();

    // Create or open evidence store
    let evidence_dir = state_dir;
    // A legacy store is archived, not refused, and a new chain starts from it (2026-10-27).
    let (store, notes) = cop_evidence::open_chain(&evidence_dir)?;
    for note in &notes {
        eprintln!("evidence: {note}");
    }
    let hmac_key = cop_evidence::load_or_create_hmac_key(&evidence_dir)?;
    check_policy_canaries(
        &chosen,
        &live_text,
        &evidence_dir,
        &store,
        &hmac_key,
        &policy_hash,
    );

    // Read JSON from stdin
    let mut stdin_data = String::new();
    io::stdin()
        .read_to_string(&mut stdin_data)
        .map_err(|e| format!("Failed to read stdin: {}", e))?;

    // SessionStart is a heartbeat, not a verdict (2026-10-27). It writes one row and prints nothing.
    if let Ok(start) = serde_json::from_str::<serde_json::Value>(&stdin_data) {
        if start["hook_event_name"].as_str() == Some("SessionStart") {
            record_heartbeat(&store, &hmac_key, &start);
            record_session_start(&evidence_dir, &start);
            return Ok(());
        }
    }

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
                let (v, r) = judge.judge_in_session(&event, session_view(&before, now.sensitive));
                (v, format!("{t}; {r}"))
            }
            None => judge.judge_in_session(&event, session_view(&before, now.sensitive)),
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
        // The HMAC is of the original input; the stored event and reason are redacted first.
        let original_input = serde_json::to_string(&event.tool_input).unwrap_or_default();
        let input_hmac = cop_evidence::input_hmac(&hmac_key, &original_input);
        let case = Case {
            event: redactor.event(&event),
            verdict,
            evidence_hash: None,
            reason: Some(redactor.text(&stored_reason)),
        };
        let row_id = store
            .append_with_input(&case, &input_hmac)
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

/// What the judge may see of the session: written files, whether a secret is held (before or in this call), and
/// when the session started (FP-1: an unchanged script may run after a secret read).
fn session_view(before: &cop_taint::Flags, now_sensitive: bool) -> cop_policy::SessionView<'_> {
    cop_policy::SessionView {
        written: &before.written,
        sensitive: before.sensitive || now_sensitive,
        started: before.started,
    }
}

/// Remember when this session's SessionStart happened (FP-1). A failure is printed, never fatal: the heartbeat
/// never blocks a session. Without it, scripts after a secret read ask.
fn record_session_start(state_dir: &std::path::Path, start: &serde_json::Value) {
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);
    let result = SessionStore::open(&state_dir.join("state.db")).and_then(|sessions| {
        sessions.update(start["session_id"].as_str(), |mut flags| {
            flags.started = Some(now);
            Ok((flags, ()))
        })
    });
    if let Err(e) = result {
        eprintln!("heartbeat: could not record the session start time: {e}");
    }
}

fn verdict_word(verdict: Verdict) -> &'static str {
    match verdict {
        Verdict::Allow => "allow",
        Verdict::Ask => "ask",
        Verdict::Deny => "deny",
    }
}

/// Policy canaries when the policy file changes (2026-10-27, item 4b 2026-10-26). The hash of the last checked live
/// policy is kept in canary.sha256. A live policy that fails a canary gets one loud warning and one evidence row
/// per change, and the hook runs the policy it chose instead (last-known-good or defaults). A live policy that
/// passes is saved as last-known-good.
fn check_policy_canaries(
    chosen: &cop_policy::Chosen,
    live_text: &str,
    state_dir: &std::path::Path,
    store: &cop_evidence::EvidenceStore,
    hmac_key: &[u8],
    policy_hash: &str,
) {
    if chosen.source == PolicySource::Live {
        save_last_known_good(state_dir, live_text, policy_hash);
    }
    let file = state_dir.join("canary.sha256");
    if fs::read_to_string(&file).unwrap_or_default().trim() == policy_hash {
        return;
    }
    if !chosen.live_failed.is_empty() {
        let failed = &chosen.live_failed;
        eprintln!(
            "WARNING: the loaded policy allows {} canary action(s): {}. Running the {} policy instead. Run `agentcop doctor`.",
            failed.len(),
            failed.join("; "),
            chosen.source.label()
        );
        let event = AgentEvent {
            hook_event_name: "PolicyCheck".to_string(),
            timestamp: String::new(),
            session_id: None,
            user_id: None,
            tool_name: "agentcop policy".to_string(),
            tool_input: serde_json::json!({ "allowed_canaries": failed, "running": chosen.source.label() }),
            context: Default::default(),
        };
        let original = serde_json::to_string(&event.tool_input).unwrap_or_default();
        let hmac = cop_evidence::input_hmac(hmac_key, &original);
        let case = Case {
            event,
            verdict: Verdict::Allow,
            evidence_hash: None,
            reason: Some(format!(
                "policy canaries allowed: {}; running {}",
                failed.join("; "),
                chosen.source.label()
            )),
        };
        if let Err(e) = store.append_with_input(&case, &hmac) {
            eprintln!("evidence: could not record the canary warning: {e}");
        }
    }
    if fs::write(&file, policy_hash).is_ok() {
        let _ = cop_core::perms::secure_file(&file);
    }
}

/// Save a passing live policy as last-known-good, with its hash (item 4b). Written 0600 through a temp file, so a
/// crash never leaves half a policy. A failure is printed, never fatal: the live policy still runs.
fn save_last_known_good(state_dir: &std::path::Path, live_text: &str, policy_hash: &str) {
    let saved_hash = state_dir.join(LASTGOOD_HASH_FILE);
    if fs::read_to_string(&saved_hash).unwrap_or_default().trim() == policy_hash {
        return;
    }
    let result = write_private_file(&state_dir.join(LASTGOOD_FILE), live_text)
        .and_then(|_| write_private_file(&saved_hash, policy_hash));
    if let Err(e) = result {
        eprintln!("policy: could not save last-known-good: {e}");
    }
}

/// Write a file through a temp name, then rename it into place. The temp file is created 0600, so the content is
/// never readable by others, whatever the umask.
fn write_private_file(path: &std::path::Path, text: &str) -> Result<(), String> {
    let mut tmp_name = path.as_os_str().to_owned();
    tmp_name.push(".tmp");
    let tmp = PathBuf::from(tmp_name);
    let mut file = fs::OpenOptions::new()
        .write(true)
        .create(true)
        .truncate(true)
        .mode(0o600)
        .open(&tmp)
        .map_err(|e| format!("create {}: {e}", tmp.display()))?;
    file.write_all(text.as_bytes())
        .map_err(|e| format!("write {}: {e}", tmp.display()))?;
    cop_core::perms::secure_file(&tmp)?;
    fs::rename(&tmp, path).map_err(|e| format!("rename into {}: {e}", path.display()))
}

fn sha256_hex(text: &str) -> String {
    format!(
        "{:x}",
        <sha2::Sha256 as sha2::Digest>::digest(text.as_bytes())
    )
}

/// SessionStart (2026-10-27): one evidence row per Claude Code session start, so a silent day is "no activity",
/// not "hook dead". Never blocks the session: a failure is printed to stderr only.
fn record_heartbeat(
    store: &cop_evidence::EvidenceStore,
    hmac_key: &[u8],
    start: &serde_json::Value,
) {
    let source = start["source"].as_str().unwrap_or("unknown").to_string();
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);
    let event = AgentEvent {
        hook_event_name: "SessionStart".to_string(),
        timestamp: format!("unix:{now}"),
        session_id: start["session_id"].as_str().map(str::to_string),
        user_id: None,
        tool_name: "session".to_string(),
        tool_input: serde_json::json!({ "source": source }),
        context: Default::default(),
    };
    let original = serde_json::to_string(&event.tool_input).unwrap_or_default();
    let hmac = cop_evidence::input_hmac(hmac_key, &original);
    let case = Case {
        event,
        verdict: Verdict::Allow,
        evidence_hash: None,
        reason: Some(format!("session start heartbeat ({source})")),
    };
    if let Err(e) = store.append_with_input(&case, &hmac) {
        eprintln!("heartbeat: could not record the session start: {e}");
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
