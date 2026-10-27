//! Egress proxy: the border between the agent and the network.
//!
//! PLAN:
//! 1. Load the policy: allowed domains and secret regexes. Refuse bad input (fail closed).
//! 2. Check a target host against the allowlist (exact or subdomain match).
//! 3. Scan plaintext URLs and request bodies for secret patterns.
//! 4. server.rs applies these per request. HTTPS (CONNECT) is host-checked only, because its body is encrypted.

pub mod server;

use regex::Regex;
use serde::Deserialize;

pub use server::serve;

/// Largest request body we will read and scan. Bigger bodies are refused.
pub const MAX_BODY_BYTES: usize = 1 << 20;

#[derive(Deserialize)]
struct PolicyFile {
    allow_domains: Vec<String>,
    #[serde(default)]
    secret_patterns: Vec<PatternSpec>,
}

#[derive(Deserialize)]
struct PatternSpec {
    name: String,
    regex: String,
}

#[derive(Debug)]
pub struct EgressPolicy {
    allow_domains: Vec<String>,
    secrets: Vec<(String, Regex)>,
}

impl EgressPolicy {
    /// Parse and compile a policy. Empty allowlist or bad regex is an error, so the proxy never starts open.
    pub fn from_toml(text: &str) -> Result<Self, String> {
        let file: PolicyFile = toml::from_str(text).map_err(|e| format!("bad policy: {e}"))?;
        if file.allow_domains.is_empty() {
            return Err("policy has no allow_domains; refusing to start".to_string());
        }
        if file.allow_domains.iter().any(|d| d.trim().is_empty()) {
            return Err("policy has an empty allow_domains entry".to_string());
        }
        let secrets = file
            .secret_patterns
            .into_iter()
            .map(|p| match Regex::new(&p.regex) {
                Ok(re) => Ok((p.name, re)),
                Err(e) => Err(format!("bad regex in '{}': {e}", p.name)),
            })
            .collect::<Result<Vec<_>, _>>()?;
        let allow_domains = file
            .allow_domains
            .iter()
            .map(|d| d.to_ascii_lowercase())
            .collect();
        Ok(Self {
            allow_domains,
            secrets,
        })
    }

    /// Allowed when the host equals an allowlist entry or ends with ".entry". Case-insensitive.
    pub fn check_host(&self, host: &str) -> Result<(), String> {
        let host = host.to_ascii_lowercase();
        let allowed = self
            .allow_domains
            .iter()
            .any(|d| host == *d || host.ends_with(&format!(".{d}")));
        if allowed {
            Ok(())
        } else {
            Err(format!("host '{host}' is not on the allowlist"))
        }
    }

    /// Blocked when any secret pattern matches. The error names the first pattern that matched.
    pub fn check_text(&self, text: &str) -> Result<(), String> {
        match self.secrets.iter().find(|(_, re)| re.is_match(text)) {
            Some((name, _)) => Err(format!("secret pattern '{name}' matched")),
            None => Ok(()),
        }
    }
}
