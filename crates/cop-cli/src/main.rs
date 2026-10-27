//! agentcop CLI: install, uninstall, cases, verify
//!
//! PLAN:
//! 1. Load Claude Code settings.json
//! 2. Implement install: add cop-hook to PreToolUse hook with onFailure: block
//! 3. Implement uninstall: restore from backup
//! 4. Implement verify: call EvidenceStore::verify()
//! 5. Implement cases: list evidence (stub for A6)
//! 6. Support --dry-run, idempotent operations

mod cases;
mod doctor;
mod evidence_cmd;
mod fix;
mod install;
mod release;

use clap::{Parser, Subcommand};

#[derive(Parser)]
#[command(name = "agentcop")]
#[command(about = "AI agent security enforcer")]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum PolicyCommand {
    /// Run the must-catch canaries against a policy file (default: the installed one). Exit 1 if any is allowed
    Check {
        /// Policy file to check
        file: Option<std::path::PathBuf>,
    },
}

#[derive(Subcommand)]
enum EvidenceCommand {
    /// Archive a legacy evidence store and anchor a new chain to it (the hook does this on its own too)
    ArchiveLegacy,
    /// Delete archived evidence (raw commands). Asks for confirmation
    PurgeLegacy,
}

/// `agentcop cases show <ID>`: one case in full
#[derive(Subcommand)]
enum CasesCommand {
    /// Show one case: its event (already redacted), verdict, reason and hash
    Show {
        /// Case ID, e.g. CASE-0123456789ab
        case_id: String,
    },
}

#[derive(Subcommand)]
enum Commands {
    /// Install agentcop into Claude Code
    Install {
        /// Dry run: show what would happen
        #[arg(long)]
        dry_run: bool,
    },
    /// Remove our hook entries from Claude Code. Evidence stays unless --purge (asks first)
    Uninstall {
        /// Also delete ~/.agentcop: evidence, archives, policy and keys
        #[arg(long)]
        purge: bool,
    },
    /// One health check: modes, hook path, binary, canaries, chain, heartbeat, mode, archives
    Doctor,
    /// Policy tools
    Policy {
        #[command(subcommand)]
        action: PolicyCommand,
    },
    /// Verify evidence chain integrity
    Verify,
    /// List cases, or show one. Filters: --today, --since, --would-block
    Cases {
        #[command(subcommand)]
        action: Option<CasesCommand>,
        /// Only cases from today (local time)
        #[arg(long)]
        today: bool,
        /// Only cases at or after this time: YYYY-MM-DD (local midnight) or an RFC 3339 time
        #[arg(long, value_name = "WHEN")]
        since: Option<String>,
        /// Only cases log-only mode did not enforce (the ones enforce mode would have stopped)
        #[arg(long)]
        would_block: bool,
    },
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
    // A pipe closed early (`agentcop cases | head -1`) should end the program quietly, as Unix tools do. Rust
    // ignores SIGPIPE, which turns the closed pipe into a panic in println!. The default action is restored here.
    // SAFETY: signal() only sets the disposition of SIGPIPE, and it runs first, before any thread exists.
    unsafe {
        libc::signal(libc::SIGPIPE, libc::SIG_DFL);
    }
    let cli = Cli::parse();

    if let Err(e) = run(cli) {
        eprintln!("Error: {}", e);
        std::process::exit(1);
    }
}

fn run(cli: Cli) -> Result<(), String> {
    match cli.command {
        Commands::Install { dry_run } => install::run(dry_run),
        Commands::Uninstall { purge } => install::uninstall(purge),
        Commands::Doctor => doctor::run(),
        Commands::Policy { action } => match action {
            PolicyCommand::Check { file } => doctor::policy_check(file),
        },
        Commands::Verify => evidence_cmd::verify(),
        Commands::Cases {
            action,
            today,
            since,
            would_block,
        } => {
            let home = dirs::home_dir().ok_or("Failed to find home directory")?;
            match action {
                Some(CasesCommand::Show { case_id }) => cases::show(&home, &case_id),
                None => {
                    let filter = cases::Filter::from_flags(today, since.as_deref(), would_block)?;
                    cases::list(&home, &filter)
                }
            }
        }
        Commands::Evidence { action } => match action {
            EvidenceCommand::ArchiveLegacy => evidence_cmd::archive_legacy(),
            EvidenceCommand::PurgeLegacy => evidence_cmd::purge_legacy(),
        },
        Commands::Fix { case_id } => fix::run(&case_id),
        Commands::Release { session } => release::run(&session),
    }
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
        assert!(matches!(cli.command, Commands::Cases { action: None, .. }));
    }
}
