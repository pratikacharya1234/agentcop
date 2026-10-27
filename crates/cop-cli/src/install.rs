//! `agentcop install` (2026-10-27). The live hook is a copy in ~/.agentcop/bin, never a build directory.
//!
//! PLAN:
//! 1. Find the hook to copy: AGENTCOP_HOOK, else `cop-hook` next to this executable. A build directory is
//!    only a source; settings.json never points there.
//! 2. ~/.agentcop and ~/.agentcop/bin are 0700. The copy is bin/cop-hook, mode 0700 (it is a program).
//! 3. Every cop-hook entry in settings.json points at the copy. The original settings.json is backed up once
//!    (an existing .bak is kept, so uninstall restores the very first version).
//! 4. The policy is never overwritten. An existing policy gets a diff against the new default, keeps its mode,
//!    custom rules, honeytokens, redact tables and hook_guard, is backed up, and is written 0600.
//! 5. Existing state is tightened: folders 0700, files 0600.
//! 6. Legacy JSON (sessions/*.json, decisions.jsonl) is imported into state.db, then moved to legacy/.
//!
//! `--dry-run` prints each step and changes nothing.

use cop_core::perms::{ensure_private_dir, set_mode};
use cop_taint::{DecisionRow, SessionStore};
use serde_json::{json, Value};
use std::collections::HashSet;
use std::fs;
use std::path::{Path, PathBuf};

/// The default policy, compiled in, so `install` works from any directory.
const DEFAULT_POLICY: &str = include_str!("../../../policy/default.toml");

pub fn run(dry_run: bool) -> Result<(), String> {
    let home = dirs::home_dir().ok_or("Failed to find home directory")?;
    let state = home.join(".agentcop");
    let bin = state.join("bin").join("cop-hook");
    let settings_path = settings_path(&home)?;
    let source = hook_source()?;

    let content = fs::read_to_string(&settings_path).map_err(|e| {
        format!(
            "Claude Code settings not found at {}: {e}",
            settings_path.display()
        )
    })?;
    let mut settings: Value = serde_json::from_str(&content)
        .map_err(|e| format!("Failed to parse settings.json: {e}"))?;
    let bin_text = bin.to_string_lossy().into_owned();
    let changed = if has_cop_hook(&settings) {
        point_hooks_at(&mut settings, &bin_text) > 0
    } else {
        add_cop_hook(&mut settings, &bin_text)?;
        true
    };

    println!("hook copy: {} -> {}", source.display(), bin.display());
    println!(
        "settings: {} {}",
        settings_path.display(),
        if changed {
            "will point cop-hook at the copy"
        } else {
            "already points at the copy"
        }
    );
    let policy_plan = policy_update(&state, dry_run)?;
    let legacy_plan = migrate_legacy(&state, dry_run)?;
    if dry_run {
        println!("dry run: nothing changed");
        return Ok(());
    }

    ensure_private_dir(&state)?;
    ensure_private_dir(&state.join("bin"))?;
    if source != bin {
        fs::copy(&source, &bin).map_err(|e| format!("copy hook: {e}"))?;
    }
    set_mode(&bin, 0o700)?;

    if changed {
        let backup = PathBuf::from(format!("{}.bak", settings_path.display()));
        if !backup.exists() {
            fs::copy(&settings_path, &backup).map_err(|e| format!("backup settings: {e}"))?;
        }
        let text =
            serde_json::to_string_pretty(&settings).map_err(|e| format!("JSON error: {e}"))?;
        fs::write(&settings_path, text).map_err(|e| format!("write settings: {e}"))?;
    }
    tighten(&state)?;
    if let Some(note) = policy_plan {
        println!("{note}");
    }
    for note in legacy_plan {
        println!("{note}");
    }
    println!("Installed cop-hook (copy at {})", bin.display());
    Ok(())
}

/// Settings file: the project's .claude/settings.json if it exists, else ~/.claude/settings.json.
fn settings_path(home: &Path) -> Result<PathBuf, String> {
    let project = std::env::current_dir()
        .ok()
        .map(|c| c.join(".claude/settings.json"));
    Ok(match project {
        Some(p) if p.exists() => p,
        _ => home.join(".claude/settings.json"),
    })
}

/// The hook binary to copy. A build directory may be the source; it is never the target.
fn hook_source() -> Result<PathBuf, String> {
    let candidate = std::env::var("AGENTCOP_HOOK")
        .ok()
        .map(PathBuf::from)
        .or_else(|| {
            std::env::current_exe()
                .ok()
                .and_then(|p| p.parent().map(|d| d.join("cop-hook")))
        })
        .ok_or("Could not find cop-hook: set AGENTCOP_HOOK or put cop-hook next to agentcop")?;
    fs::canonicalize(&candidate)
        .map_err(|e| format!("cop-hook not found at {}: {e}", candidate.display()))
}

/// True if any hooks.PreToolUse matcher group already runs cop-hook.
pub fn has_cop_hook(settings: &Value) -> bool {
    settings["hooks"]["PreToolUse"]
        .as_array()
        .is_some_and(|groups| {
            groups.iter().any(|group| {
                group["hooks"].as_array().is_some_and(|hooks| {
                    hooks.iter().any(|h| {
                        h["command"]
                            .as_str()
                            .is_some_and(|c| c.contains("cop-hook"))
                    })
                })
            })
        })
}

/// Point every cop-hook command at `bin`. Returns how many changed.
fn point_hooks_at(settings: &mut Value, bin: &str) -> usize {
    let mut changed = 0;
    if let Some(groups) = settings["hooks"]["PreToolUse"].as_array_mut() {
        for group in groups {
            if let Some(hooks) = group["hooks"].as_array_mut() {
                for hook in hooks {
                    let is_ours = hook["command"]
                        .as_str()
                        .is_some_and(|c| c.contains("cop-hook"));
                    if is_ours && hook["command"].as_str() != Some(bin) {
                        hook["command"] = json!(bin);
                        changed += 1;
                    }
                }
            }
        }
    }
    changed
}

/// Append our matcher group to hooks.PreToolUse, creating the keys if needed.
fn add_cop_hook(settings: &mut Value, hook_path: &str) -> Result<(), String> {
    let root = settings
        .as_object_mut()
        .ok_or("settings.json must contain a JSON object")?;
    let hooks = root
        .entry("hooks")
        .or_insert_with(|| json!({}))
        .as_object_mut()
        .ok_or("settings.json \"hooks\" must be an object")?;
    let pre_tool_use = hooks
        .entry("PreToolUse")
        .or_insert_with(|| json!([]))
        .as_array_mut()
        .ok_or("settings.json \"hooks.PreToolUse\" must be an array")?;
    pre_tool_use.push(json!({
        "matcher": "*",
        "hooks": [{
            "type": "command",
            "command": hook_path,
            "onFailure": "block"
        }]
    }));
    Ok(())
}

/// Policy update. Returns a note when the policy was written (None when nothing changed or on dry run).
fn policy_update(state: &Path, dry_run: bool) -> Result<Option<String>, String> {
    let path = state.join("policy.toml");
    if !path.exists() {
        println!(
            "policy: will install the default policy to {}",
            path.display()
        );
        if dry_run {
            return Ok(None);
        }
        ensure_private_dir(state)?;
        fs::write(&path, DEFAULT_POLICY).map_err(|e| format!("write policy: {e}"))?;
        set_mode(&path, 0o600)?;
        return Ok(Some(format!(
            "Installed default policy to {}",
            path.display()
        )));
    }
    let old = fs::read_to_string(&path).map_err(|e| format!("read policy: {e}"))?;
    let new = merged_policy(&old)?;
    if new == old {
        println!("policy: up to date ({})", path.display());
        return Ok(None);
    }
    println!(
        "policy diff ({} -> new default with your settings):",
        path.display()
    );
    for line in diff_lines(&old, &new).iter().take(60) {
        println!("  {line}");
    }
    if dry_run {
        return Ok(None);
    }
    let backup = state.join(format!("policy.toml.bak-{}", unix_now()));
    fs::copy(&path, &backup).map_err(|e| format!("backup policy: {e}"))?;
    set_mode(&backup, 0o600)?;
    fs::write(&path, &new).map_err(|e| format!("write policy: {e}"))?;
    set_mode(&path, 0o600)?;
    Ok(Some(format!(
        "Updated policy; backup at {}",
        backup.display()
    )))
}

/// The new default policy, with the user's mode, custom rules, honeytokens, redact tables and hook_guard kept.
/// The result must load as a policy; otherwise nothing is written.
fn merged_policy(old: &str) -> Result<String, String> {
    let user: toml::Table =
        toml::from_str(old).map_err(|e| format!("current policy does not parse: {e}"))?;
    let default: toml::Table =
        toml::from_str(DEFAULT_POLICY).map_err(|e| format!("default policy: {e}"))?;
    let default_patterns = |key: &str| -> HashSet<String> {
        default
            .get(key)
            .and_then(|v| v.as_array())
            .into_iter()
            .flatten()
            .filter_map(|r| r["pattern"].as_str().map(str::to_string))
            .collect()
    };
    let custom = |key: &str| -> Vec<toml::Value> {
        let known = default_patterns(key);
        user.get(key)
            .and_then(|v| v.as_array())
            .into_iter()
            .flatten()
            .filter(|r| r["pattern"].as_str().is_some_and(|p| !known.contains(p)))
            .cloned()
            .collect()
    };
    let mut extras = toml::Table::new();
    for key in ["rules", "honeytokens"] {
        let items = custom(key);
        if !items.is_empty() {
            extras.insert(key.to_string(), toml::Value::Array(items));
        }
    }
    // Redaction: the built-in list is in the binary. Keep only tables the built-in list does not have.
    let builtin: HashSet<String> = cop_policy::builtin_redact_rules()?
        .into_iter()
        .map(|r| r.pattern)
        .collect();
    let extra_redact: Vec<toml::Value> = user
        .get("redact")
        .and_then(|v| v.as_array())
        .into_iter()
        .flatten()
        .filter(|r| r["pattern"].as_str().is_some_and(|p| !builtin.contains(p)))
        .cloned()
        .collect();
    if !extra_redact.is_empty() {
        extras.insert("redact".to_string(), toml::Value::Array(extra_redact));
    }
    if let Some(off) = user.get("redact").and_then(|v| v.as_str()) {
        extras.insert("redact".to_string(), toml::Value::String(off.to_string()));
    }
    if let Some(guard) = user.get("hook_guard") {
        extras.insert("hook_guard".to_string(), guard.clone());
    }
    let mode = user
        .get("mode")
        .and_then(|v| v.as_str())
        .unwrap_or("enforce");
    let mut text = DEFAULT_POLICY.replacen("mode = \"enforce\"", &format!("mode = \"{mode}\""), 1);
    if !extras.is_empty() {
        text.push_str("\n# Your settings, kept by `agentcop install`.\n");
        text.push_str(
            &toml::to_string(&extras).map_err(|e| format!("serialize your settings: {e}"))?,
        );
    }
    toml::from_str::<cop_policy::Policy>(&text)
        .map_err(|e| format!("merged policy does not load: {e}"))?;
    Ok(text)
}

/// A plain line diff: lines only in `old` as "-", lines only in `new` as "+". Not a true LCS diff.
fn diff_lines(old: &str, new: &str) -> Vec<String> {
    let old_set: HashSet<&str> = old.lines().collect();
    let new_set: HashSet<&str> = new.lines().collect();
    let mut out: Vec<String> = old
        .lines()
        .filter(|l| !new_set.contains(l))
        .map(|l| format!("- {l}"))
        .collect();
    out.extend(
        new.lines()
            .filter(|l| !old_set.contains(l))
            .map(|l| format!("+ {l}")),
    );
    out
}

/// Folders 0700, files 0600, one level deep in the state folder (the bin folder keeps its program at 0700).
fn tighten(state: &Path) -> Result<(), String> {
    ensure_private_dir(state)?;
    for entry in fs::read_dir(state).map_err(|e| format!("read state folder: {e}"))? {
        let path = entry.map_err(|e| e.to_string())?.path();
        if path.is_dir() {
            ensure_private_dir(&path)?;
        } else if path.is_file() {
            set_mode(&path, 0o600)?;
        }
    }
    Ok(())
}

/// Import sessions/*.json and decisions.jsonl into state.db, then move them to legacy/.
fn migrate_legacy(state: &Path, dry_run: bool) -> Result<Vec<String>, String> {
    let mut notes = Vec::new();
    let sessions_dir = state.join("sessions");
    let decisions_file = state.join("decisions.jsonl");
    let session_files: Vec<PathBuf> = if sessions_dir.is_dir() {
        fs::read_dir(&sessions_dir)
            .map_err(|e| format!("read sessions: {e}"))?
            .filter_map(|e| e.ok().map(|e| e.path()))
            .filter(|p| p.extension().is_some_and(|x| x == "json"))
            .collect()
    } else {
        Vec::new()
    };
    let decisions_exist = decisions_file.is_file();
    if session_files.is_empty() && !decisions_exist {
        return Ok(notes);
    }
    notes.push(format!(
        "legacy: {} session file(s), decisions.jsonl {}",
        session_files.len(),
        if decisions_exist { "present" } else { "absent" }
    ));
    if dry_run {
        return Ok(notes);
    }
    let store = SessionStore::open(&state.join("state.db"))?;
    for file in &session_files {
        let digest = file
            .file_stem()
            .and_then(|s| s.to_str())
            .unwrap_or("unknown");
        let text = fs::read_to_string(file).map_err(|e| format!("read {}: {e}", file.display()))?;
        store.import_legacy_session(digest, &text)?;
    }
    if decisions_exist {
        let text =
            fs::read_to_string(&decisions_file).map_err(|e| format!("read decisions: {e}"))?;
        for line in text.lines().filter(|l| !l.trim().is_empty()) {
            let v: Value =
                serde_json::from_str(line).map_err(|e| format!("decisions.jsonl line: {e}"))?;
            store.import_decision(&DecisionRow {
                seq: v["seq"].as_i64().unwrap_or(0),
                case_id: v["case_id"].as_str().unwrap_or("").to_string(),
                action: v["action"].as_str().unwrap_or("").to_string(),
                at: v["at"].as_str().unwrap_or("").to_string(),
                prev: v["prev"].as_str().unwrap_or("").to_string(),
                hash: v["hash"].as_str().unwrap_or("").to_string(),
            })?;
        }
    }
    let legacy = state.join("legacy");
    ensure_private_dir(&legacy)?;
    if sessions_dir.is_dir() {
        fs::rename(&sessions_dir, legacy.join("sessions"))
            .map_err(|e| format!("archive sessions: {e}"))?;
    }
    if decisions_exist {
        fs::rename(&decisions_file, legacy.join("decisions.jsonl"))
            .map_err(|e| format!("archive decisions: {e}"))?;
        set_mode(&legacy.join("decisions.jsonl"), 0o600)?;
    }
    notes.push(format!(
        "legacy: imported into state.db and moved to {}",
        legacy.display()
    ));
    Ok(notes)
}

fn unix_now() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}
