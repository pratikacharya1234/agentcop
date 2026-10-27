//! agentcop CLI: install, uninstall, cases, verify
//!
//! PLAN:
//! 1. Load Claude Code settings.json
//! 2. Implement install: add cop-hook to PreToolUse hook with onFailure: block
//! 3. Implement uninstall: restore from backup
//! 4. Implement verify: call EvidenceStore::verify()
//! 5. Implement cases: list evidence (stub for A6)
//! 6. Support --dry-run, idempotent operations

mod fix;

use clap::{Parser, Subcommand};
use cop_evidence::EvidenceStore;
use serde_json::{json, Value};
use std::fs;
use std::path::PathBuf;

#[derive(Parser)]
#[command(name = "agentcop")]
#[command(about = "AI agent security enforcer")]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    /// Install agentcop into Claude Code
    Install {
        /// Dry run: show what would happen
        #[arg(long)]
        dry_run: bool,
    },
    /// Uninstall agentcop from Claude Code
    Uninstall,
    /// Verify evidence chain integrity
    Verify,
    /// List recent cases
    Cases,
    /// Suggest a deny rule for a case, show the diff, and ask before applying
    Fix {
        /// Case ID, e.g. CASE-0123456789ab
        case_id: String,
    },
}

fn main() {
    let cli = Cli::parse();

    if let Err(e) = run(cli) {
        eprintln!("Error: {}", e);
        std::process::exit(1);
    }
}

fn run(cli: Cli) -> Result<(), String> {
    match cli.command {
        Commands::Install { dry_run } => install(dry_run),
        Commands::Uninstall => uninstall(),
        Commands::Verify => verify(),
        Commands::Cases => cases(),
        Commands::Fix { case_id } => fix::run(&case_id),
    }
}

fn install(dry_run: bool) -> Result<(), String> {
    // Find settings.json at ~/.claude/settings.json (per Claude Code docs)
    // Try project-local .claude/settings.json first, then ~/.claude/settings.json
    let home_dir = dirs::home_dir().ok_or("Failed to find home directory")?;
    let settings_path = if let Ok(cwd) = std::env::current_dir() {
        let project_settings = cwd.join(".claude/settings.json");
        if project_settings.exists() {
            project_settings
        } else {
            home_dir.join(".claude/settings.json")
        }
    } else {
        home_dir.join(".claude/settings.json")
    };

    if !settings_path.exists() {
        return Err(format!(
            "Claude Code settings not found at {}. Expected ~/.claude/settings.json",
            settings_path.display()
        ));
    }

    // Read settings
    let content = fs::read_to_string(&settings_path)
        .map_err(|e| format!("Failed to read settings.json: {}", e))?;
    let mut settings: Value = serde_json::from_str(&content)
        .map_err(|e| format!("Failed to parse settings.json: {}", e))?;

    // Check if already installed
    if has_cop_hook(&settings) {
        if !dry_run {
            ensure_policy(&home_dir)?;
        }
        println!("cop-hook already installed");
        return Ok(());
    }

    // Find cop-hook binary path
    // First try: same directory as agentcop binary
    // Then try: common installation paths
    // Then try: from AGENTCOP_HOOK env var
    let hook_path = std::env::var("AGENTCOP_HOOK")
        .ok()
        .or_else(|| {
            std::env::current_exe()
                .ok()
                .and_then(|p| p.parent().map(|parent| parent.join("cop-hook")))
                .and_then(|p| if p.exists() { Some(p.to_string_lossy().into_owned()) } else { None })
        })
        .or_else(|| {
            let home = dirs::home_dir()?;
            let agentcop_path = home.join(".agentcop/cop-hook");
            if agentcop_path.exists() {
                Some(agentcop_path.to_string_lossy().into_owned())
            } else {
                None
            }
        })
        .ok_or_else(|| {
            "Could not find cop-hook binary. Set AGENTCOP_HOOK env var or ensure cop-hook is in same directory as agentcop".to_string()
        })?;
    // Claude Code needs an absolute path to a real file; refuse to install a dangling hook
    let hook_path = fs::canonicalize(&hook_path)
        .map_err(|e| format!("cop-hook not found at {}: {}", hook_path, e))?
        .to_string_lossy()
        .into_owned();

    // Append one matcher group under hooks.PreToolUse (other keys and groups are kept)
    add_cop_hook(&mut settings, &hook_path)?;

    if dry_run {
        println!("Would write to: {}", settings_path.display());
        let pretty =
            serde_json::to_string_pretty(&settings).map_err(|e| format!("JSON error: {}", e))?;
        println!("Settings: {}", pretty);
        return Ok(());
    }

    ensure_policy(&home_dir)?;

    // Backup
    let backup_path = format!("{}.bak", settings_path.display());
    fs::copy(&settings_path, &backup_path).map_err(|e| format!("Failed to backup: {}", e))?;

    // Write updated settings
    let updated =
        serde_json::to_string_pretty(&settings).map_err(|e| format!("JSON error: {}", e))?;
    fs::write(&settings_path, updated).map_err(|e| format!("Failed to write settings: {}", e))?;

    println!("Installed cop-hook to Claude Code");
    println!("Backup saved to: {}", backup_path);
    Ok(())
}

/// The default policy, compiled in, so `install` works from any directory.
const DEFAULT_POLICY: &str = include_str!("../../../policy/default.toml");

/// Copy the default policy to ~/.agentcop/policy.toml if missing. Never overwrites.
fn ensure_policy(home_dir: &std::path::Path) -> Result<(), String> {
    let policy_path = home_dir.join(".agentcop/policy.toml");
    if policy_path.exists() {
        return Ok(());
    }
    if let Some(dir) = policy_path.parent() {
        fs::create_dir_all(dir).map_err(|e| format!("Failed to create ~/.agentcop: {}", e))?;
    }
    fs::write(&policy_path, DEFAULT_POLICY)
        .map_err(|e| format!("Failed to write policy: {}", e))?;
    println!("Installed default policy to: {}", policy_path.display());
    Ok(())
}

/// True if any hooks.PreToolUse matcher group already runs cop-hook.
fn has_cop_hook(settings: &Value) -> bool {
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

fn uninstall() -> Result<(), String> {
    let home_dir = dirs::home_dir().ok_or("Failed to find home directory")?;
    let settings_path = if let Ok(cwd) = std::env::current_dir() {
        let project_settings = cwd.join(".claude/settings.json");
        if project_settings.exists() {
            project_settings
        } else {
            home_dir.join(".claude/settings.json")
        }
    } else {
        home_dir.join(".claude/settings.json")
    };
    let backup_path = format!("{}.bak", settings_path.display());

    if !PathBuf::from(&backup_path).exists() {
        return Err("No backup found. Was agentcop ever installed?".to_string());
    }

    fs::copy(&backup_path, &settings_path).map_err(|e| format!("Failed to restore: {}", e))?;

    println!("Uninstalled cop-hook from Claude Code");
    println!("Settings restored from: {}", backup_path);
    Ok(())
}

fn verify() -> Result<(), String> {
    let evidence_path = dirs::home_dir()
        .ok_or("Failed to find home directory")?
        .join(".agentcop/evidence.db");

    if !evidence_path.exists() {
        println!("No evidence database found");
        return Ok(());
    }

    let store = EvidenceStore::new(&evidence_path)
        .map_err(|e| format!("Failed to open evidence store: {}", e))?;

    store
        .verify()
        .map_err(|e| format!("Evidence chain verification failed: {}", e))?;

    println!("Evidence chain verified successfully");
    Ok(())
}

fn cases() -> Result<(), String> {
    let evidence_path = dirs::home_dir()
        .ok_or("Failed to find home directory")?
        .join(".agentcop/evidence.db");

    if !evidence_path.exists() {
        println!("No cases yet");
        return Ok(());
    }

    let store = EvidenceStore::new(&evidence_path)
        .map_err(|e| format!("Failed to open evidence store: {}", e))?;

    let rows = store
        .find_by_hash_prefix("")
        .map_err(|e| format!("Failed to list cases: {}", e))?;

    println!("Total cases: {}", rows.len());
    for row in rows {
        // Same ID that `agentcop fix` accepts: CASE- plus the first 12 hex characters of the hash.
        let id: String = row.hash.chars().take(12).collect();
        println!(
            "CASE-{id}  {:<5}  {}  {}",
            row.verdict, row.timestamp, row.reason
        );
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn can_parse_install_command() {
        let cli = Cli::try_parse_from(vec!["agentcop", "install"]).expect("Failed to parse");
        assert!(matches!(cli.command, Commands::Install { dry_run: false }));
    }

    #[test]
    fn can_parse_install_dry_run() {
        let cli =
            Cli::try_parse_from(vec!["agentcop", "install", "--dry-run"]).expect("Failed to parse");
        assert!(matches!(cli.command, Commands::Install { dry_run: true }));
    }

    #[test]
    fn can_parse_verify_command() {
        let cli = Cli::try_parse_from(vec!["agentcop", "verify"]).expect("Failed to parse");
        assert!(matches!(cli.command, Commands::Verify));
    }

    #[test]
    fn can_parse_cases_command() {
        let cli = Cli::try_parse_from(vec!["agentcop", "cases"]).expect("Failed to parse");
        assert!(matches!(cli.command, Commands::Cases));
    }
}
