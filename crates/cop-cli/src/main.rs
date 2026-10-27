//! agentcop CLI: install, uninstall, cases, verify
//!
//! PLAN:
//! 1. Load Claude Code settings.json
//! 2. Implement install: add cop-hook to PreToolUse hook with onFailure: block
//! 3. Implement uninstall: restore from backup
//! 4. Implement verify: call EvidenceStore::verify()
//! 5. Implement cases: list evidence (stub for A6)
//! 6. Support --dry-run, idempotent operations

mod evidence_cmd;
mod fix;
mod install;
mod release;

use clap::{Parser, Subcommand};
use cop_evidence::EvidenceStore;
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
enum EvidenceCommand {
    /// Archive a legacy evidence store and anchor a new chain to it (the hook does this on its own too)
    ArchiveLegacy,
    /// Delete archived evidence (raw commands). Asks for confirmation
    PurgeLegacy,
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
    /// Evidence housekeeping: archive legacy evidence, or purge archives (asks first)
    Evidence {
        #[command(subcommand)]
        action: EvidenceCommand,
    },
    /// End a Rule of Two freeze. Asks first; the release is logged with who and when
    Release {
        /// Session ID, as the freeze message names it
        session: String,
    },
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
        Commands::Install { dry_run } => install::run(dry_run),
        Commands::Uninstall => uninstall(),
        Commands::Verify => evidence_cmd::verify(),
        Commands::Cases => cases(),
        Commands::Evidence { action } => match action {
            EvidenceCommand::ArchiveLegacy => evidence_cmd::archive_legacy(),
            EvidenceCommand::PurgeLegacy => evidence_cmd::purge_legacy(),
        },
        Commands::Fix { case_id } => fix::run(&case_id),
        Commands::Release { session } => release::run(&session),
    }
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
