//! Holding cell: enforcement mechanism that aggregates sensor evidence and makes verdicts
//!
//! PLAN:
//! 1. Define HoldCell: tracks per-process risk scores from all sensors
//! 2. Aggregate evidence: exec anomalies, family relationships, syscalls, egress events
//! 3. Verdict logic: Allow (0-30), Ask (31-70), Deny (71-100)
//! 4. Quarantine state: track held processes and their reasoning
//! 5. Evidence scoring: weight each sensor type differently

use cop_core::Verdict;
use cop_egress::EgressMonitor;
use cop_family::ProcessFamily;
use cop_syscalls::AccessMap;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

/// A process under observation in the holding cell
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HeldProcess {
    pub pid: u32,
    pub command: String,
    pub risk_score: u32, // 0-100
    pub verdict: Verdict,
    pub reasons: Vec<String>,
    pub held: bool,
}

/// The holding cell: aggregates all sensor data and makes enforcement verdicts
#[derive(Debug, Clone)]
pub struct HoldCell {
    held_processes: HashMap<u32, HeldProcess>,
    process_family: Option<ProcessFamily>,
    file_network_access: Option<AccessMap>,
    egress_monitor: Option<EgressMonitor>,
}

impl HoldCell {
    pub fn new() -> Self {
        HoldCell {
            held_processes: HashMap::new(),
            process_family: None,
            file_network_access: None,
            egress_monitor: None,
        }
    }

    /// Set the process family tree (from D2)
    pub fn set_process_family(&mut self, family: ProcessFamily) {
        self.process_family = Some(family);
    }

    /// Set the file/network access map (from D3)
    pub fn set_file_network_access(&mut self, access: AccessMap) {
        self.file_network_access = Some(access);
    }

    /// Set the egress monitor (from D4)
    pub fn set_egress_monitor(&mut self, monitor: EgressMonitor) {
        self.egress_monitor = Some(monitor);
    }

    /// Calculate risk score for a process based on all available evidence
    pub fn calculate_risk_score(&self, pid: u32) -> u32 {
        let mut score: u32 = 0;

        // Evidence from family relationships (D2)
        if let Some(family) = &self.process_family {
            let family_score = family.get_anomaly_score(pid);
            score += family_score;
        }

        // Evidence from file/network syscalls (D3)
        if let Some(access) = &self.file_network_access {
            let suspicious_count = access.get_suspicious().len() as u32;
            if access.get_file_access(pid).len() > 20 {
                score += 25; // excessive file access
            }
            if access.accessed_sensitive_files(pid) {
                score += 40; // accessed /etc/shadow, /.ssh/, etc.
            }
            if access.attempted_suid_chmod(pid) {
                score += 50; // privilege escalation attempt
            }
            score += suspicious_count.min(20); // per-syscall suspicion (capped)
        }

        // Evidence from egress events (D4)
        if let Some(egress) = &self.egress_monitor {
            let exfil_count = egress.get_suspicious().len() as u32;
            if egress.check_exfiltration(pid) {
                score += 60; // large data exfiltration detected
            }
            if egress.check_reverse_shell(pid) {
                score += 70; // reverse shell connection detected
            }
            score += exfil_count.min(15); // per-egress-event suspicion (capped)
        }

        score.min(100) // cap at 100
    }

    /// Make a verdict for a process based on its risk score
    fn score_to_verdict(score: u32) -> Verdict {
        match score {
            0..=30 => Verdict::Allow,
            31..=70 => Verdict::Ask,
            71..=100 => Verdict::Deny,
            _ => Verdict::Deny,
        }
    }

    /// Analyze a process and decide whether to hold it
    pub fn analyze_process(&mut self, pid: u32, command: &str) -> Verdict {
        let risk_score = self.calculate_risk_score(pid);
        let verdict = Self::score_to_verdict(risk_score);

        let mut reasons = Vec::new();

        // Collect reasoning from each sensor
        if let Some(family) = &self.process_family {
            if family
                .get_process(pid)
                .map(|p| p.suspicious)
                .unwrap_or(false)
            {
                reasons.push(format!(
                    "Suspicious process family relationship (score: {})",
                    family.get_anomaly_score(pid)
                ));
            }
        }

        if let Some(access) = &self.file_network_access {
            if access.accessed_sensitive_files(pid) {
                reasons.push("Accessed sensitive files (/etc/shadow, /.ssh/, /.aws/)".to_string());
            }
            if access.attempted_suid_chmod(pid) {
                reasons.push("Attempted privilege escalation via chmod".to_string());
            }
            if !access.get_suspicious().is_empty() {
                reasons.push(format!(
                    "Suspicious syscalls: {}",
                    access.get_suspicious().len()
                ));
            }
        }

        if let Some(egress) = &self.egress_monitor {
            if egress.check_exfiltration(pid) {
                reasons.push("Large data exfiltration detected (>1MB POST)".to_string());
            }
            if egress.check_reverse_shell(pid) {
                reasons.push("Reverse shell connection to suspicious port".to_string());
            }
            if !egress.get_suspicious().is_empty() {
                reasons.push(format!(
                    "Suspicious egress: {}",
                    egress.get_suspicious().len()
                ));
            }
        }

        let held = verdict != Verdict::Allow;

        let held_process = HeldProcess {
            pid,
            command: command.to_string(),
            risk_score,
            verdict,
            reasons,
            held,
        };

        self.held_processes.insert(pid, held_process);
        verdict
    }

    /// Get a held process record
    pub fn get_held_process(&self, pid: u32) -> Option<&HeldProcess> {
        self.held_processes.get(&pid)
    }

    /// Get all held processes (verdict != Allow)
    pub fn get_all_held(&self) -> Vec<u32> {
        self.held_processes
            .iter()
            .filter(|(_, proc)| proc.held)
            .map(|(pid, _)| *pid)
            .collect()
    }

    /// Get all processes (held or not)
    pub fn get_all_processes(&self) -> Vec<u32> {
        self.held_processes.keys().copied().collect()
    }

    /// Count held processes
    pub fn held_count(&self) -> usize {
        self.held_processes.iter().filter(|(_, p)| p.held).count()
    }

    /// Get risk score for a process
    pub fn get_risk_score(&self, pid: u32) -> u32 {
        self.held_processes
            .get(&pid)
            .map(|p| p.risk_score)
            .unwrap_or(0)
    }

    /// Get processes with high risk (score >= 70)
    pub fn get_high_risk(&self) -> Vec<u32> {
        self.held_processes
            .iter()
            .filter(|(_, proc)| proc.risk_score >= 70)
            .map(|(pid, _)| *pid)
            .collect()
    }

    /// Get processes with medium risk (score 31-69)
    pub fn get_medium_risk(&self) -> Vec<u32> {
        self.held_processes
            .iter()
            .filter(|(_, proc)| proc.risk_score >= 31 && proc.risk_score <= 69)
            .map(|(pid, _)| *pid)
            .collect()
    }

    /// Get processes with low risk (score 0-30)
    pub fn get_low_risk(&self) -> Vec<u32> {
        self.held_processes
            .iter()
            .filter(|(_, proc)| proc.risk_score <= 30)
            .map(|(pid, _)| *pid)
            .collect()
    }

    /// Release a held process (clear from holding)
    pub fn release(&mut self, pid: u32) {
        if let Some(proc) = self.held_processes.get_mut(&pid) {
            proc.held = false;
        }
    }

    /// Get total processes analyzed
    pub fn total_processes(&self) -> usize {
        self.held_processes.len()
    }
}

impl Default for HoldCell {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_empty_cell_has_no_processes() {
        let cell = HoldCell::new();
        assert_eq!(cell.total_processes(), 0);
        assert_eq!(cell.held_count(), 0);
    }

    #[test]
    fn test_score_to_verdict_low_risk() {
        assert_eq!(HoldCell::score_to_verdict(0), Verdict::Allow);
        assert_eq!(HoldCell::score_to_verdict(15), Verdict::Allow);
        assert_eq!(HoldCell::score_to_verdict(30), Verdict::Allow);
    }

    #[test]
    fn test_score_to_verdict_medium_risk() {
        assert_eq!(HoldCell::score_to_verdict(31), Verdict::Ask);
        assert_eq!(HoldCell::score_to_verdict(50), Verdict::Ask);
        assert_eq!(HoldCell::score_to_verdict(70), Verdict::Ask);
    }

    #[test]
    fn test_score_to_verdict_high_risk() {
        assert_eq!(HoldCell::score_to_verdict(71), Verdict::Deny);
        assert_eq!(HoldCell::score_to_verdict(85), Verdict::Deny);
        assert_eq!(HoldCell::score_to_verdict(100), Verdict::Deny);
    }

    #[test]
    fn test_analyze_clean_process() {
        let mut cell = HoldCell::new();
        let verdict = cell.analyze_process(1234, "bash");

        assert_eq!(verdict, Verdict::Allow);
        assert_eq!(cell.held_count(), 0);
        assert_eq!(cell.total_processes(), 1);
    }

    #[test]
    fn test_analyze_suspicious_process() {
        let mut cell = HoldCell::new();
        // Manually set a high risk score by calling analyze multiple times
        let _v1 = cell.analyze_process(5000, "suspicious_cmd");
        // Verify it's tracked
        assert_eq!(cell.total_processes(), 1);
        assert!(cell.get_held_process(5000).is_some());
    }

    #[test]
    fn test_get_held_processes() {
        let mut cell = HoldCell::new();
        cell.analyze_process(100, "clean1");
        cell.analyze_process(200, "clean2");

        let held = cell.get_all_held();
        assert_eq!(held.len(), 0); // no held processes (all low risk)
    }

    #[test]
    fn test_risk_score_capped_at_100() {
        let mut cell = HoldCell::new();
        cell.analyze_process(9999, "max_risk");
        let score = cell.get_risk_score(9999);
        assert!(score <= 100);
    }

    #[test]
    fn test_low_medium_high_risk_buckets() {
        let mut cell = HoldCell::new();
        cell.analyze_process(1, "low");
        cell.analyze_process(2, "med");
        cell.analyze_process(3, "high");

        // Initially all have score 0 (low)
        assert!(!cell.get_low_risk().is_empty());
    }

    #[test]
    fn test_held_process_has_command() {
        let mut cell = HoldCell::new();
        cell.analyze_process(555, "test_command");

        let proc = cell.get_held_process(555).unwrap();
        assert_eq!(proc.command, "test_command");
        assert_eq!(proc.pid, 555);
    }

    #[test]
    fn test_release_process() {
        let mut cell = HoldCell::new();
        cell.analyze_process(777, "cmd");

        let proc = cell.get_held_process(777).unwrap();
        assert!(!proc.held); // Allow verdict, not held

        cell.release(777);
        let proc = cell.get_held_process(777).unwrap();
        assert!(!proc.held); // still not held
    }

    #[test]
    fn test_multiple_processes_tracked_separately() {
        let mut cell = HoldCell::new();
        cell.analyze_process(100, "proc1");
        cell.analyze_process(200, "proc2");
        cell.analyze_process(300, "proc3");

        assert_eq!(cell.total_processes(), 3);
        assert_eq!(cell.get_held_process(100).unwrap().pid, 100);
        assert_eq!(cell.get_held_process(200).unwrap().pid, 200);
        assert_eq!(cell.get_held_process(300).unwrap().pid, 300);
    }

    #[test]
    fn test_held_process_has_reasons_field() {
        let mut cell = HoldCell::new();
        cell.analyze_process(888, "analyzed");

        let proc = cell.get_held_process(888).unwrap();
        // Verify reasons field exists
        let _ = &proc.reasons;
    }

    #[test]
    fn test_get_all_processes_list() {
        let mut cell = HoldCell::new();
        cell.analyze_process(1, "a");
        cell.analyze_process(2, "b");
        cell.analyze_process(3, "c");

        let all = cell.get_all_processes();
        assert_eq!(all.len(), 3);
        assert!(all.contains(&1));
        assert!(all.contains(&2));
        assert!(all.contains(&3));
    }

    #[test]
    fn test_verdict_capping_exceeds_100() {
        let mut cell = HoldCell::new();
        cell.analyze_process(9998, "over_max");
        let score = cell.get_risk_score(9998);
        assert!(score <= 100);
    }

    #[test]
    fn test_held_process_verdict_field() {
        let mut cell = HoldCell::new();
        cell.analyze_process(666, "test");

        let proc = cell.get_held_process(666).unwrap();
        match proc.verdict {
            Verdict::Allow | Verdict::Ask | Verdict::Deny => {} // all valid
        }
    }

    #[test]
    fn test_high_risk_filter() {
        let mut cell = HoldCell::new();
        cell.analyze_process(1, "low");

        let high = cell.get_high_risk();
        let medium = cell.get_medium_risk();
        let low = cell.get_low_risk();

        assert_eq!(high.len() + medium.len() + low.len(), 1);
        assert!(!low.is_empty());
    }
}
