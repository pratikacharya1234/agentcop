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
//! 7. Policy canaries (2026-10-27): the policy that would be installed must not allow any canary action
//!    (cop_policy::canaries). If one is allowed, install prints the names and refuses, before any write.
//! 8. The hook is registered for PreToolUse (every tool call) and SessionStart (one heartbeat row per session).
//!
//! `--dry-run` prints each step and changes nothing.

use cop_core::perms::{ensure_private_dir, set_mode};
use cop_taint::{DecisionRow, SessionStore};
use serde_json::{json, Value};
use std::collections::HashSet;
use std::fs;
use std::path::{Path, PathBuf};

/// The default policy, compiled in, so `install` works from any directory.
/// `AGENTCOP_DEFAULT_POLICY` (a file path) replaces it. It exists for tests of the canary gate; the gate applies
/// to whatever it reads.
const COMPILED_POLICY: &str = include_str!("../../../policy/default.toml");

fn default_policy() -> Result<String, String> {
    match std::env::var("AGENTCOP_DEFAULT_POLICY") {
        Ok(path) => fs::read_to_string(&path).map_err(|e| format!("AGENTCOP_DEFAULT_POLICY: {e}")),
        Err(_) => Ok(COMPILED_POLICY.to_string()),
    }
}

/// The hook events AgentCop registers (2026-10-27).
const EVENTS: [&str; 2] = ["PreToolUse", "SessionStart"];

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
    let mut changed = point_hooks_at(&mut settings, &bin_text) > 0;
    for event in EVENTS {
        if !event_has_cop_hook(&settings, event) {
            add_cop_hook(&mut settings, event, &bin_text)?;
            changed = true;
        }
    }

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
pub fn settings_path(home: &Path) -> Result<PathBuf, String> {
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

/// True if any matcher group under `event` already runs cop-hook.
fn event_has_cop_hook(settings: &Value, event: &str) -> bool {
    settings["hooks"][event].as_array().is_some_and(|groups| {
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

/// Point every cop-hook command, under every event, at `bin`. Returns how many changed.
fn point_hooks_at(settings: &mut Value, bin: &str) -> usize {
    let mut changed = 0;
    for event in EVENTS {
        // get_mut, not settings["hooks"][event]: IndexMut would insert a null for a missing key.
        let groups = settings
            .get_mut("hooks")
            .and_then(|h| h.get_mut(event))
            .and_then(|g| g.as_array_mut());
        if let Some(groups) = groups {
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
    }
    changed
}

/// Append our matcher group under `event`, creating the keys if needed. PreToolUse fails closed (block);
/// SessionStart is a heartbeat and never blocks a session.
fn add_cop_hook(settings: &mut Value, event: &str, hook_path: &str) -> Result<(), String> {
    let root = settings
        .as_object_mut()
        .ok_or("settings.json must contain a JSON object")?;
    let hooks = root
        .entry("hooks")
        .or_insert_with(|| json!({}))
        .as_object_mut()
        .ok_or("settings.json \"hooks\" must be an object")?;
    let groups = hooks
        .entry(event)
        .or_insert_with(|| json!([]))
        .as_array_mut()
        .ok_or_else(|| format!("settings.json \"hooks.{event}\" must be an array"))?;
    let entry = if event == "PreToolUse" {
        json!({ "type": "command", "command": hook_path, "onFailure": "block" })
    } else {
        json!({ "type": "command", "command": hook_path })
    };
    groups.push(json!({ "matcher": "*", "hooks": [entry] }));
    Ok(())
}

/// Remove every matcher group that runs cop-hook, under every event. Other hooks are kept. Returns how many
/// cop-hook commands were removed.
fn remove_cop_hooks(settings: &mut Value) -> usize {
    let mut removed = 0;
    // get_mut, not settings["hooks"]: IndexMut would insert a null "hooks" key into a file that has none.
    let Some(hooks) = settings.get_mut("hooks").and_then(|h| h.as_object_mut()) else {
        return 0;
    };
    for event in EVENTS {
        let Some(groups) = hooks.get_mut(event).and_then(|g| g.as_array_mut()) else {
            continue;
        };
        for group in groups.iter_mut() {
            if let Some(list) = group["hooks"].as_array_mut() {
                let before = list.len();
                list.retain(|h| {
                    !h["command"]
                        .as_str()
                        .is_some_and(|c| c.contains("cop-hook"))
                });
                removed += before - list.len();
            }
        }
        groups.retain(|g| g["hooks"].as_array().is_none_or(|l| !l.is_empty()));
        if groups.is_empty() {
            hooks.remove(event);
        }
    }
    if hooks.is_empty() {
        settings.as_object_mut().map(|o| o.remove("hooks"));
    }
    removed
}

/// Refuse a policy that allows any canary action. Prints the names; writes nothing.
fn canary_gate(text: &str) -> Result<(), String> {
    let policy: cop_policy::Policy =
        toml::from_str(text).map_err(|e| format!("policy does not load: {e}"))?;
    let judge =
        cop_policy::Judge::new(policy).map_err(|e| format!("policy does not compile: {e}"))?;
    let allowed: Vec<&str> = cop_policy::run_canaries(&judge)
        .into_iter()
        .filter(|r| !r.passed)
        .map(|r| r.name)
        .collect();
    if allowed.is_empty() {
        return Ok(());
    }
    for name in &allowed {
        eprintln!("WARNING: canary allowed: {name}");
    }
    Err(format!(
        "refusing to install this policy: it allows {} canary action(s): {}. Restore the default rule for them (copy policy/default.toml).",
        allowed.len(),
        allowed.join("; ")
    ))
}

/// Policy update. Returns a note when the policy was written (None when nothing changed or on dry run).
fn policy_update(state: &Path, dry_run: bool) -> Result<Option<String>, String> {
    let path = state.join("policy.toml");
    if !path.exists() {
        let text = default_policy()?;
        canary_gate(&text)?;
        println!(
            "policy: will install the default policy to {}",
            path.display()
        );
        if dry_run {
            return Ok(None);
        }
        ensure_private_dir(state)?;
        fs::write(&path, &text).map_err(|e| format!("write policy: {e}"))?;
        set_mode(&path, 0o600)?;
        return Ok(Some(format!(
            "Installed default policy to {}",
            path.display()
        )));
    }
    let old = fs::read_to_string(&path).map_err(|e| format!("read policy: {e}"))?;
    let new = merged_policy(&old)?;
    canary_gate(&new)?;
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
    let default_text = default_policy()?;
    let default: toml::Table =
        toml::from_str(&default_text).map_err(|e| format!("default policy: {e}"))?;
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
    let mut text = default_text.replacen("mode = \"enforce\"", &format!("mode = \"{mode}\""), 1);
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

/// `agentcop uninstall` (2026-10-27). Removes only our hook entries. If that leaves exactly the backup's content,
/// the backup's bytes are restored. Evidence and state stay, unless `--purge` (which asks first).
pub fn uninstall(purge: bool) -> Result<(), String> {
    let home = dirs::home_dir().ok_or("Failed to find home directory")?;
    let state = home.join(".agentcop");
    let settings_path = settings_path(&home)?;
    let content = fs::read_to_string(&settings_path)
        .map_err(|e| format!("read {}: {e}", settings_path.display()))?;
    let mut settings: Value =
        serde_json::from_str(&content).map_err(|e| format!("parse settings.json: {e}"))?;
    let removed = remove_cop_hooks(&mut settings);
    let backup = PathBuf::from(format!("{}.bak", settings_path.display()));
    let original_text = fs::read_to_string(&backup).ok();
    let original_value: Option<Value> = original_text
        .as_deref()
        .and_then(|t| serde_json::from_str(t).ok());
    if removed == 0 {
        println!(
            "No AgentCop hook entries found in {}",
            settings_path.display()
        );
    } else if original_value.as_ref() == Some(&settings) {
        fs::write(&settings_path, original_text.unwrap_or_default())
            .map_err(|e| format!("restore settings: {e}"))?;
        println!(
            "Removed {removed} AgentCop hook entries; settings are byte-identical to the backup."
        );
    } else {
        let text =
            serde_json::to_string_pretty(&settings).map_err(|e| format!("JSON error: {e}"))?;
        fs::write(&settings_path, text).map_err(|e| format!("write settings: {e}"))?;
        println!(
            "Removed {removed} AgentCop hook entries. The rest of the file is kept as it is now; the backup differs, so it was not restored."
        );
    }
    let bin = state.join("bin").join("cop-hook");
    if bin.exists() {
        fs::remove_file(&bin).map_err(|e| format!("remove {}: {e}", bin.display()))?;
        println!("Removed the hook copy {}", bin.display());
    }
    if purge {
        println!(
            "--purge deletes ALL AgentCop state: evidence, archives, policy and keys ({}).",
            state.display()
        );
        print!("Delete it? [y/N] ");
        std::io::Write::flush(&mut std::io::stdout()).map_err(|e| e.to_string())?;
        let mut answer = String::new();
        std::io::BufRead::read_line(&mut std::io::stdin().lock(), &mut answer)
            .map_err(|e| format!("read answer: {e}"))?;
        if matches!(answer.trim().to_lowercase().as_str(), "y" | "yes") {
            fs::remove_dir_all(&state).map_err(|e| format!("remove {}: {e}", state.display()))?;
            println!("Deleted {}", state.display());
        } else {
            println!("Nothing deleted. Evidence stays in {}", state.display());
        }
    } else if state.exists() {
        println!(
            "Evidence and state stay in {} (use --purge to delete them).",
            state.display()
        );
    }
    Ok(())
}
