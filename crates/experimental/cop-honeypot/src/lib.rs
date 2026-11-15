//! Honeypot traps: fake credentials, canary hosts, decoy files
//!
//! PLAN:
//! 1. HoneypotType enum: FakeCredential, CanaryHost, DecoyFile
//! 2. Trap struct: pattern, type, decoy_value, alert
//! 3. HoneypotDetector: check event against all traps
//! 4. Tests: detect fakes, no false positives, alert on hit

use cop_core::AgentEvent;
use regex::Regex;

/// Type of honeypot trap
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HoneypotType {
    FakeCredential,
    CanaryHost,
    DecoyFile,
}

/// A honeypot trap
#[derive(Debug, Clone)]
pub struct Trap {
    pub name: String,
    pub trap_type: HoneypotType,
    pub pattern: String,
    pub decoy_value: String,
    pub alert_message: String,
}

impl Trap {
    /// Create a fake credential trap (e.g., AWS key)
    pub fn fake_credential(name: &str, pattern: &str, decoy: &str, alert: &str) -> Self {
        Trap {
            name: name.to_string(),
            trap_type: HoneypotType::FakeCredential,
            pattern: pattern.to_string(),
            decoy_value: decoy.to_string(),
            alert_message: alert.to_string(),
        }
    }

    /// Create a canary host trap (e.g., internal.example.com)
    pub fn canary_host(name: &str, pattern: &str, decoy: &str, alert: &str) -> Self {
        Trap {
            name: name.to_string(),
            trap_type: HoneypotType::CanaryHost,
            pattern: pattern.to_string(),
            decoy_value: decoy.to_string(),
            alert_message: alert.to_string(),
        }
    }

    /// Create a decoy file trap (e.g., /root/.ssh/admin_key)
    pub fn decoy_file(name: &str, pattern: &str, decoy: &str, alert: &str) -> Self {
        Trap {
            name: name.to_string(),
            trap_type: HoneypotType::DecoyFile,
            pattern: pattern.to_string(),
            decoy_value: decoy.to_string(),
            alert_message: alert.to_string(),
        }
    }
}

/// Honeypot detector: check events against traps
pub struct HoneypotDetector {
    traps: Vec<(Trap, Regex)>,
}

impl HoneypotDetector {
    /// Create a new detector with default traps.
    ///
    /// The AWS trap only matches our own decoy, which always carries the marker `AKIAFAKE`.
    /// A real AWS access key id has the shape `AKIA` plus 16 upper-case letters and digits, so a
    /// pattern that matches that shape would trip on every real key the agent happens to see. The
    /// marker keeps the trap honest: only our fake bait is caught (ADR 27, FP-1 follow-up).
    pub fn new() -> Result<Self, String> {
        let default_traps = vec![
            Trap::fake_credential(
                "AWS key",
                r"AKIAFAKE[0-9A-Z]{12}",
                "AKIAFAKEFAKEFAKEFAKE",
                "Fake AWS key detected in command",
            ),
            Trap::canary_host(
                "Internal DB",
                r"(canary\.internal|honeypot\.local)",
                "canary.internal",
                "Access to canary host attempted",
            ),
            Trap::decoy_file(
                "Admin SSH key",
                r"(admin_key|superuser_key|root_key)",
                "/root/.ssh/admin_key",
                "Attempt to access decoy SSH key",
            ),
        ];

        Self::with_traps(default_traps)
    }

    /// Create a detector with custom traps
    pub fn with_traps(traps: Vec<Trap>) -> Result<Self, String> {
        let mut compiled = Vec::new();

        for trap in traps {
            let regex = Regex::new(&trap.pattern).map_err(|e| format!("Invalid regex: {}", e))?;
            compiled.push((trap, regex));
        }

        Ok(HoneypotDetector { traps: compiled })
    }

    /// Check an event against all traps
    pub fn check(&self, event: &AgentEvent) -> Option<String> {
        let event_str = format!(
            "{} {} {}",
            event.tool_name,
            serde_json::to_string(&event.tool_input).unwrap_or_default(),
            event
                .context
                .values()
                .map(|v| v.to_string())
                .collect::<Vec<_>>()
                .join(" ")
        );

        for (trap, regex) in &self.traps {
            if regex.is_match(&event_str) {
                return Some(trap.alert_message.clone());
            }
        }

        None
    }

    /// Get the number of traps
    pub fn trap_count(&self) -> usize {
        self.traps.len()
    }
}

impl Default for HoneypotDetector {
    fn default() -> Self {
        Self::new().expect("Failed to create default HoneypotDetector")
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashMap;

    fn sample_event(command: &str) -> AgentEvent {
        AgentEvent {
            hook_event_name: "PreToolUse".to_string(),
            timestamp: "2026-10-20T10:00:00Z".to_string(),
            session_id: Some("s123".to_string()),
            user_id: Some("u456".to_string()),
            tool_name: "bash".to_string(),
            tool_input: serde_json::json!({"command": command}),
            context: HashMap::new(),
        }
    }

    #[test]
    fn detect_fake_aws_key() {
        let detector = HoneypotDetector::new().expect("Creation failed");
        let event = sample_event("aws configure set aws_access_key_id AKIAFAKEFAKEFAKEFAKE");

        let alert = detector.check(&event);
        assert!(alert.is_some());
        assert!(alert.unwrap().contains("AWS"));
    }

    #[test]
    fn detect_canary_host() {
        let detector = HoneypotDetector::new().expect("Creation failed");
        let event = sample_event("mysql -h canary.internal -u admin");

        let alert = detector.check(&event);
        assert!(alert.is_some());
        assert!(alert.unwrap().contains("canary"));
    }

    #[test]
    fn detect_decoy_file() {
        let detector = HoneypotDetector::new().expect("Creation failed");
        let event = sample_event("cat /root/.ssh/admin_key");

        let alert = detector.check(&event);
        assert!(alert.is_some());
        assert!(alert.unwrap().contains("SSH"));
    }

    #[test]
    fn no_match_on_legitimate_commands() {
        let detector = HoneypotDetector::new().expect("Creation failed");
        let event = sample_event("ls -la /home/user");

        let alert = detector.check(&event);
        assert!(alert.is_none());
    }

    #[test]
    fn no_match_on_real_shaped_aws_keys() {
        let detector = HoneypotDetector::new().expect("Creation failed");
        // A real AWS access key id has the shape AKIA + 16 upper-case letters and digits. The
        // honeytoken must not fire on one, or a real key in a log or a test fixture would be
        // reported as "the suspect took the bait" (FP-1 follow-up).
        for key in [
            "AKIAIOSFODNN7EXAMPLE",
            "AKIA123456789ABCDE",
            "AKIAQWERTYUIOPASDFG",
        ] {
            let event = sample_event(&format!("aws configure set aws_access_key_id {key}"));
            let alert = detector.check(&event);
            assert!(
                alert.is_none(),
                "a real-shaped key {key} must not trip the honeytoken"
            );
        }
    }

    #[test]
    fn custom_trap() {
        let custom_trap = Trap::fake_credential(
            "Test key",
            r"TEST_KEY_[0-9]{6}",
            "TEST_KEY_123456",
            "Test trap triggered",
        );
        let detector = HoneypotDetector::with_traps(vec![custom_trap])
            .expect("Creation with custom trap failed");

        let event = sample_event("export SECRET=TEST_KEY_654321");
        let alert = detector.check(&event);

        assert!(alert.is_some());
        assert_eq!(alert.unwrap(), "Test trap triggered");
    }

    #[test]
    fn trap_creation_helpers() {
        let cred_trap = Trap::fake_credential("cred", "pattern", "decoy", "alert");
        assert_eq!(cred_trap.trap_type, HoneypotType::FakeCredential);

        let host_trap = Trap::canary_host("host", "pattern", "decoy", "alert");
        assert_eq!(host_trap.trap_type, HoneypotType::CanaryHost);

        let file_trap = Trap::decoy_file("file", "pattern", "decoy", "alert");
        assert_eq!(file_trap.trap_type, HoneypotType::DecoyFile);
    }

    #[test]
    fn detector_default_has_traps() {
        let detector = HoneypotDetector::default();
        assert!(detector.trap_count() > 0);
    }
}
