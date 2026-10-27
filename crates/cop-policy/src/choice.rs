//! Which policy text the hook runs (item 4b, 2026-10-26). PLAN:
//! 1. Judge the live policy against the canaries. If it passes, it runs.
//! 2. If it fails, run the last-known-good copy, but only if that copy passes the canaries too.
//! 3. If neither passes, run the built-in defaults (compiled in). Never an empty or weaker policy.
//! 4. A policy that does not load or compile is an error, not a fallback. The hook then fails closed.
//!
//! Edge cases: a missing last-known-good means step 3. A last-known-good that fails is never used.

use crate::{run_canaries, Judge, Policy};

/// The shipped policy, compiled in. The last resort when no saved policy passes the canaries.
const BUILTIN: &str = include_str!("../../../policy/default.toml");

/// File names in the state folder (`~/.agentcop/`). The hash file holds the SHA-256 of the saved policy text.
pub const LASTGOOD_FILE: &str = "policy.lastgood.toml";
pub const LASTGOOD_HASH_FILE: &str = "policy.lastgood.sha256";

/// Where the chosen policy came from.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PolicySource {
    Live,
    LastGood,
    Builtin,
}

impl PolicySource {
    /// The words used in warnings and in `agentcop doctor`.
    pub fn label(self) -> &'static str {
        match self {
            PolicySource::Live => "live",
            PolicySource::LastGood => "last-known-good",
            PolicySource::Builtin => "built-in defaults",
        }
    }
}

/// The policy text to run, where it came from, and the canaries the live policy allows.
pub struct Chosen {
    pub text: String,
    pub source: PolicySource,
    pub live_failed: Vec<&'static str>,
}

/// Canary names this policy text allows. Err when the text does not load or compile.
pub fn canary_failures(text: &str) -> Result<Vec<&'static str>, String> {
    let policy: Policy = toml::from_str(text).map_err(|e| format!("policy does not load: {e}"))?;
    let judge = Judge::new(policy).map_err(|e| format!("policy does not compile: {e}"))?;
    Ok(run_canaries(&judge)
        .into_iter()
        .filter(|r| !r.passed)
        .map(|r| r.name)
        .collect())
}

/// Pick the policy to run. `lastgood` is the saved copy, if there is one.
pub fn choose_policy(live: &str, lastgood: Option<&str>) -> Result<Chosen, String> {
    let live_failed = canary_failures(live)?;
    if live_failed.is_empty() {
        return Ok(Chosen {
            text: live.to_string(),
            source: PolicySource::Live,
            live_failed,
        });
    }
    if let Some(good) = lastgood {
        if canary_failures(good).is_ok_and(|failed| failed.is_empty()) {
            return Ok(Chosen {
                text: good.to_string(),
                source: PolicySource::LastGood,
                live_failed,
            });
        }
    }
    Ok(Chosen {
        text: BUILTIN.to_string(),
        source: PolicySource::Builtin,
        live_failed,
    })
}

/// The built-in policy text (what `install` writes on a fresh machine).
pub fn builtin_text() -> &'static str {
    BUILTIN
}
