//! `agentcop fix CASE-<id>`: suggest a deny rule for a case, show the diff, and apply only on yes.
//!
//! PLAN:
//! 1. Parse the case ID (`CASE-` + 12 hex chars, as cop-bundle prints it). Anything else is an error.
//! 2. Find exactly one evidence row with that hash prefix. Zero or several is an error.
//! 3. Refuse allow-verdict cases (nothing to fix) and tools with no `command` field (no suggestion).
//! 4. Suggest a deny rule that matches the exact `"command":"..."` text the judge sees (regex-escaped).
//! 5. Show the diff, then ask `Apply? [y/N]`. Only y or yes applies.
//! 6. Before writing: the new policy must parse and compile. Back up the old file, write a temp file, rename it into place.

use cop_core::AgentEvent;
use cop_evidence::EvidenceStore;
use cop_policy::{Judge, Policy, Rule};
use serde::Serialize;
use std::fs;
use std::io::{self, BufRead, Write};
use std::path::{Path, PathBuf};

pub fn run(case_id: &str) -> Result<(), String> {
    let prefix = parse_case_id(case_id)?;
    let db = home()?.join(".agentcop/evidence.db");
    if !db.exists() {
        return Err("no evidence store yet; there are no cases to fix".to_string());
    }
    let store = EvidenceStore::new(&db).map_err(|e| format!("open evidence store: {e}"))?;
    let rows = store
        .find_by_hash_prefix(&prefix)
        .map_err(|e| format!("read evidence: {e}"))?;
    let row = match rows.as_slice() {
        [one] => one,
        [] => return Err(format!("no case matches {case_id}")),
        _ => {
            return Err(format!(
                "{case_id} matches more than one case; refusing to guess"
            ))
        }
    };
    if row.verdict == "allow" {
        return Err(format!("{case_id} was allowed; nothing to fix"));
    }
    let event: AgentEvent = serde_json::from_str(&row.event_json)
        .map_err(|e| format!("stored event is unreadable: {e}"))?;
    let rule = suggest_rule(&event, case_id)?;

    let path = policy_path()?;
    let current =
        fs::read_to_string(&path).map_err(|e| format!("read policy {}: {e}", path.display()))?;
    let proposed = append_rule(&current, &rule)?;
    print_diff(&path, &rule);

    print!("Apply? [y/N] ");
    io::stdout().flush().map_err(|e| e.to_string())?;
    let mut answer = String::new();
    io::stdin()
        .lock()
        .read_line(&mut answer)
        .map_err(|e| e.to_string())?;
    if matches!(answer.trim().to_ascii_lowercase().as_str(), "y" | "yes") {
        write_policy(&path, &current, &proposed)?;
        println!("Applied. Backup at {}", backup_path(&path).display());
    } else {
        println!("No change made.");
    }
    Ok(())
}

/// The deny rule that stops exactly this command. Verdict is always deny, never allow.
pub fn suggest_rule(event: &AgentEvent, case_id: &str) -> Result<Rule, String> {
    let command = event
        .tool_input
        .get("command")
        .and_then(|v| v.as_str())
        .ok_or_else(|| {
            format!(
                "no automatic suggestion for tool {}: it has no command field",
                event.tool_name
            )
        })?;
    // The judge matches "<tool_name> <tool_input as compact JSON>". This is the exact text for this command.
    let needle = format!(
        "\"command\":{}",
        serde_json::to_string(command).map_err(|e| e.to_string())?
    );
    Ok(Rule {
        pattern: regex::escape(&needle),
        scope: Some(event.tool_name.clone()),
        verdict: "deny".to_string(),
        reason: Some(format!("Blocked by {case_id} (agentcop fix)")),
    })
}

fn parse_case_id(case_id: &str) -> Result<String, String> {
    let hex = case_id
        .strip_prefix("CASE-")
        .filter(|h| h.len() == 12 && h.chars().all(|c| c.is_ascii_hexdigit()))
        .ok_or_else(|| {
            format!("bad case id {case_id}; expected CASE- followed by 12 hex characters")
        })?;
    Ok(hex.to_ascii_lowercase())
}

/// Same order as the hook: AGENTCOP_POLICY first, then ~/.agentcop/policy.toml.
fn policy_path() -> Result<PathBuf, String> {
    match std::env::var_os("AGENTCOP_POLICY") {
        Some(p) => Ok(PathBuf::from(p)),
        None => Ok(home()?.join(".agentcop/policy.toml")),
    }
}

fn home() -> Result<PathBuf, String> {
    dirs::home_dir().ok_or_else(|| "Failed to find home directory".to_string())
}

fn backup_path(policy: &Path) -> PathBuf {
    policy.with_file_name("policy.toml.bak")
}

/// Append one rule block. The result must still parse and compile, or nothing is written.
fn append_rule(current: &str, rule: &Rule) -> Result<String, String> {
    let block = rule_block(rule);
    let proposed = format!("{current}\n{block}");
    let policy: Policy =
        toml::from_str(&proposed).map_err(|e| format!("proposed policy does not parse: {e}"))?;
    Judge::new(policy).map_err(|e| format!("proposed policy does not compile: {e}"))?;
    Ok(proposed)
}

fn print_diff(path: &Path, rule: &Rule) {
    let block = rule_block(rule);
    println!("--- {}", path.display());
    println!("+++ {} (proposed)", path.display());
    for line in block.lines() {
        println!("+{line}");
    }
}

/// One `[[rules]]` block, TOML-escaped, ready to append to the policy file.
fn rule_block(rule: &Rule) -> String {
    #[derive(Serialize)]
    struct Wrapper<'a> {
        rules: Vec<&'a Rule>,
    }
    toml::to_string(&Wrapper { rules: vec![rule] }).unwrap_or_default()
}

fn write_policy(path: &Path, current: &str, proposed: &str) -> Result<(), String> {
    fs::write(backup_path(path), current).map_err(|e| format!("write backup: {e}"))?;
    let tmp = path.with_file_name("policy.toml.tmp");
    fs::write(&tmp, proposed).map_err(|e| format!("write temp policy: {e}"))?;
    fs::rename(&tmp, path).map_err(|e| format!("replace policy: {e}"))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashMap;

    #[test]
    fn suggested_pattern_escapes_regex_characters() {
        let event = AgentEvent {
            hook_event_name: "PreToolUse".to_string(),
            timestamp: String::new(),
            session_id: None,
            user_id: None,
            tool_name: "Bash".to_string(),
            tool_input: serde_json::json!({ "command": "a.b*c" }),
            context: HashMap::new(),
        };
        let rule = suggest_rule(&event, "CASE-0123456789ab").unwrap();
        assert_eq!(rule.verdict, "deny");
        let re = regex::Regex::new(&rule.pattern).unwrap();
        assert!(re.is_match(&event.tool_input.to_string()));
        assert!(!re.is_match(r#"{"command":"aXb*c"}"#));
    }
}
