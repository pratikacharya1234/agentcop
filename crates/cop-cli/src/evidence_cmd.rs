//! `agentcop verify`, `agentcop evidence archive-legacy` and `agentcop evidence purge-legacy` (2026-10-27).
//!
//! PLAN:
//! 1. verify: the current chain must verify; it reports its anchor (the archive it continues from, if any).
//! 2. verify also reports the newest archive: its final hash, and whether the current chain's anchor matches it.
//! 3. archive-legacy: the same archiving the hook does on its own (for a manual run). It never deletes anything.
//! 4. purge-legacy: lists the archives (raw commands: evidence-legacy*.db and evidence-interim-*.db), with sizes,
//!    and asks before deleting anything (2026-10-27).

use cop_evidence::{final_hash, latest_archive, open_chain, EvidenceStore};
use std::fs;
use std::io::{self, BufRead, Write};
use std::path::{Path, PathBuf};

fn state_dir() -> Result<PathBuf, String> {
    Ok(dirs::home_dir()
        .ok_or("Failed to find home directory")?
        .join(".agentcop"))
}

pub fn verify() -> Result<(), String> {
    let dir = state_dir()?;
    let current = dir.join("evidence.db");
    if !current.exists() {
        println!("No evidence database found");
        return Ok(());
    }
    let store =
        EvidenceStore::open_existing(&current).map_err(|e| format!("open evidence: {e}"))?;
    store
        .verify()
        .map_err(|e| format!("Evidence chain verification failed: {e}"))?;
    let rows = store.count().map_err(|e| format!("count: {e}"))?;
    println!("Evidence chain verified successfully ({rows} rows)");
    let anchor = store.anchor().map_err(|e| format!("anchor: {e}"))?;
    match (&anchor, latest_archive(&dir)) {
        (Some(hash), Some(archive)) => {
            let archived = final_hash(&archive)?;
            let ok = *hash == archived;
            println!(
                "anchor: continues from {} (final hash {})",
                archive.display(),
                short(&archived)
            );
            println!(
                "anchor matches the archive: {}",
                if ok { "yes" } else { "NO" }
            );
            if !ok {
                return Err(
                    "the current chain does not continue from the newest archive".to_string(),
                );
            }
        }
        (None, Some(archive)) => {
            println!(
                "note: the current chain has no anchor; the archive {} is not linked",
                archive.display()
            );
        }
        (_, None) => println!("anchor: none (no archived evidence)"),
    }
    Ok(())
}

pub fn archive_legacy() -> Result<(), String> {
    let dir = state_dir()?;
    let (_store, notes) = open_chain(&dir)?;
    if notes.is_empty() {
        println!("Nothing to archive: the evidence chain is current.");
    }
    for note in notes {
        println!("{note}");
    }
    Ok(())
}

pub fn purge_legacy() -> Result<(), String> {
    let dir = state_dir()?;
    let archives = raw_archives(&dir);
    if archives.is_empty() {
        println!("No archived evidence to purge.");
        return Ok(());
    }
    println!("These files hold raw commands and will be deleted permanently:");
    for a in &archives {
        let kb = fs::metadata(a).map(|m| m.len() / 1024).unwrap_or(0);
        println!("  {} ({} KB)", a.display(), kb);
    }
    print!("Delete them? [y/N] ");
    io::stdout().flush().map_err(|e| e.to_string())?;
    let mut answer = String::new();
    io::stdin()
        .lock()
        .read_line(&mut answer)
        .map_err(|e| format!("read answer: {e}"))?;
    if !matches!(answer.trim().to_lowercase().as_str(), "y" | "yes") {
        println!("Nothing deleted.");
        return Ok(());
    }
    for a in &archives {
        fs::remove_file(a).map_err(|e| format!("delete {}: {e}", a.display()))?;
        for suffix in ["-wal", "-shm", "-journal"] {
            let companion = PathBuf::from(format!("{}{suffix}", a.display()));
            if companion.exists() {
                fs::remove_file(&companion)
                    .map_err(|e| format!("delete {}: {e}", companion.display()))?;
            }
        }
    }
    println!("Deleted {} archive(s).", archives.len());
    Ok(())
}

/// Every archive that holds raw commands: evidence-legacy*.db and evidence-interim-*.db (2026-10-27).
pub fn raw_archives(dir: &Path) -> Vec<PathBuf> {
    let mut out: Vec<PathBuf> = fs::read_dir(dir)
        .into_iter()
        .flatten()
        .filter_map(|e| e.ok().map(|e| e.path()))
        .filter(|p| {
            p.file_name().and_then(|n| n.to_str()).is_some_and(|n| {
                (n.starts_with("evidence-legacy") || n.starts_with("evidence-interim"))
                    && n.ends_with(".db")
            })
        })
        .collect();
    out.sort();
    out
}

fn short(hash: &str) -> &str {
    &hash[..hash.len().min(16)]
}
