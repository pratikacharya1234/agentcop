//! Sound asset registry and loading
//!
//! Maps SoundEvent to audio file paths and handles fallback to silence

use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::path::PathBuf;

use crate::SoundEvent;

/// Sound asset mapping
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SoundAssets {
    assets: HashMap<String, String>,
}

impl SoundAssets {
    /// Load assets from TOML string
    pub fn from_toml(toml: &str) -> Result<Self, String> {
        #[derive(Deserialize)]
        struct AssetConfig {
            sounds: HashMap<String, String>,
        }

        let config: AssetConfig =
            toml::from_str(toml).map_err(|e| format!("TOML parse error: {}", e))?;
        Ok(SoundAssets {
            assets: config.sounds,
        })
    }

    /// Get asset path for a sound event
    pub fn get_path(&self, event: SoundEvent) -> Option<PathBuf> {
        let key = match event {
            SoundEvent::Allow => "allow",
            SoundEvent::Ask => "ask",
            SoundEvent::Deny => "deny",
            SoundEvent::Honeytoken => "honeytoken",
            SoundEvent::Frozen => "frozen",
            SoundEvent::Gavel => "gavel",
            SoundEvent::CaseClosed => "case_closed",
        };

        self.assets.get(key).map(PathBuf::from)
    }

    /// Check if all required events have assets
    pub fn all_events_mapped(&self) -> bool {
        let events = [
            "allow",
            "ask",
            "deny",
            "honeytoken",
            "frozen",
            "gavel",
            "case_closed",
        ];
        events.iter().all(|e| self.assets.contains_key(*e))
    }

    /// Get count of mapped assets
    pub fn count(&self) -> usize {
        self.assets.len()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_valid_toml() {
        let toml = r#"
[sounds]
allow = "/usr/share/agentcop/chime.wav"
ask = "/usr/share/agentcop/chirp.wav"
deny = "/usr/share/agentcop/honk.wav"
"#;
        let assets = SoundAssets::from_toml(toml).expect("Parse failed");
        assert_eq!(assets.count(), 3);
    }

    #[test]
    fn invalid_toml_returns_error() {
        let bad_toml = r#"
[sounds
invalid syntax
"#;
        let result = SoundAssets::from_toml(bad_toml);
        assert!(result.is_err());
    }

    #[test]
    fn get_path_for_event() {
        let toml = r#"
[sounds]
allow = "/path/to/chime.wav"
ask = "/path/to/chirp.wav"
deny = "/path/to/honk.wav"
honeytoken = "/path/to/alarm.wav"
frozen = "/path/to/laser.wav"
gavel = "/path/to/gavel.wav"
case_closed = "/path/to/jingle.wav"
"#;
        let assets = SoundAssets::from_toml(toml).expect("Parse failed");

        assert_eq!(
            assets.get_path(SoundEvent::Allow),
            Some(PathBuf::from("/path/to/chime.wav"))
        );
        assert_eq!(
            assets.get_path(SoundEvent::Deny),
            Some(PathBuf::from("/path/to/honk.wav"))
        );
    }

    #[test]
    fn missing_event_returns_none() {
        let toml = r#"
[sounds]
allow = "/path/to/chime.wav"
"#;
        let assets = SoundAssets::from_toml(toml).expect("Parse failed");
        assert!(assets.get_path(SoundEvent::Deny).is_none());
    }

    #[test]
    fn all_events_mapped_checks_completeness() {
        let complete_toml = r#"
[sounds]
allow = "/path/allow.wav"
ask = "/path/ask.wav"
deny = "/path/deny.wav"
honeytoken = "/path/honeytoken.wav"
frozen = "/path/frozen.wav"
gavel = "/path/gavel.wav"
case_closed = "/path/case_closed.wav"
"#;
        let assets = SoundAssets::from_toml(complete_toml).expect("Parse failed");
        assert!(assets.all_events_mapped());

        let incomplete_toml = r#"
[sounds]
allow = "/path/allow.wav"
"#;
        let assets = SoundAssets::from_toml(incomplete_toml).expect("Parse failed");
        assert!(!assets.all_events_mapped());
    }
}
