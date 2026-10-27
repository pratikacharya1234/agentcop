//! agentcop CLI: install, uninstall, cases, verify
//!
//! PLAN:
//! 1. Load Claude Code settings.json
//! 2. Implement install: add cop-hook to PreToolUse hook with onFailure: block
//! 3. Implement uninstall: restore from backup
//! 4. Implement verify: call EvidenceStore::verify()
//! 5. Implement cases: list evidence (stub for A6)
//! 6. Support --dry-run, idempotent operations

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
    if let Some(hooks) = settings.get("PreToolUse") {
        if hooks.as_array().is_some_and(|arr| {
            arr.iter().any(|h| {
                h.get("hookPath")
                    .and_then(|v| v.as_str())
                    .is_some_and(|p| p.contains("cop-hook"))
            })
        }) {
            println!("cop-hook already installed");
            return Ok(());
        }
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

    // Add the hook with absolute path
    let hook = json!({
        "hookPath": hook_path,
        "onFailure": "block"
    });

    settings["PreToolUse"] = settings.get("PreToolUse").cloned().unwrap_or(json!([]));
    if let Some(arr) = settings["PreToolUse"].as_array_mut() {
        arr.push(hook);
    }

    if dry_run {
        println!("Would write to: {}", settings_path.display());
        let pretty =
            serde_json::to_string_pretty(&settings).map_err(|e| format!("JSON error: {}", e))?;
        println!("Settings: {}", pretty);
        return Ok(());
    }

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

    let count = store
        .count()
        .map_err(|e| format!("Failed to count cases: {}", e))?;

    println!("Total cases: {}", count);
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
