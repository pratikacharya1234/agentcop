//! Case bundle: collects and organizes all sensor evidence into coherent case files
//!
//! PLAN:
//! 1. Define Evidence: structured collection of findings from each sensor (D1-D5)
//! 2. Define CaseFile: wraps agent event + all evidence + verdict + metadata
//! 3. Collect from sensors: exec events, family relationships, syscalls, egress, risk scores
//! 4. Build summaries: per-sensor evidence rolls into bullet points
//! 5. Track timeline: when each piece of evidence was collected

use cop_core::{AgentEvent, Verdict};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

/// Evidence collected from one sensor phase
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SensorEvidence {
    pub phase: String, // "D1", "D2", etc.
    pub findings: Vec<String>,
    pub severity: String, // "low", "medium", "high"
    pub event_count: usize,
}

impl SensorEvidence {
    pub fn new(phase: &str) -> Self {
        SensorEvidence {
            phase: phase.to_string(),
            findings: Vec::new(),
            severity: "low".to_string(),
            event_count: 0,
        }
    }

    pub fn add_finding(&mut self, finding: impl Into<String>) {
        self.findings.push(finding.into());
    }

    pub fn set_severity(&mut self, severity: &str) {
        self.severity = severity.to_string();
    }
}

/// All evidence collected for a single case
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EvidenceBundle {
    pub exec_evidence: Option<SensorEvidence>,    // D1
    pub family_evidence: Option<SensorEvidence>,  // D2
    pub syscall_evidence: Option<SensorEvidence>, // D3
    pub egress_evidence: Option<SensorEvidence>,  // D4
    pub risk_evidence: Option<SensorEvidence>,    // D5
}

impl EvidenceBundle {
    pub fn new() -> Self {
        EvidenceBundle {
            exec_evidence: None,
            family_evidence: None,
            syscall_evidence: None,
            egress_evidence: None,
            risk_evidence: None,
        }
    }

    /// Add evidence from D1 (execution)
    pub fn add_exec_evidence(&mut self, evidence: SensorEvidence) {
        self.exec_evidence = Some(evidence);
    }

    /// Add evidence from D2 (family)
    pub fn add_family_evidence(&mut self, evidence: SensorEvidence) {
        self.family_evidence = Some(evidence);
    }

    /// Add evidence from D3 (syscalls)
    pub fn add_syscall_evidence(&mut self, evidence: SensorEvidence) {
        self.syscall_evidence = Some(evidence);
    }

    /// Add evidence from D4 (egress)
    pub fn add_egress_evidence(&mut self, evidence: SensorEvidence) {
        self.egress_evidence = Some(evidence);
    }

    /// Add evidence from D5 (risk)
    pub fn add_risk_evidence(&mut self, evidence: SensorEvidence) {
        self.risk_evidence = Some(evidence);
    }

    /// Get all non-empty evidence sources
    pub fn get_sources(&self) -> Vec<&SensorEvidence> {
        let mut sources = Vec::new();
        if let Some(e) = &self.exec_evidence {
            sources.push(e);
        }
        if let Some(e) = &self.family_evidence {
            sources.push(e);
        }
        if let Some(e) = &self.syscall_evidence {
            sources.push(e);
        }
        if let Some(e) = &self.egress_evidence {
            sources.push(e);
        }
        if let Some(e) = &self.risk_evidence {
            sources.push(e);
        }
        sources
    }

    /// Count total findings across all sources
    pub fn total_findings(&self) -> usize {
        self.get_sources().iter().map(|e| e.findings.len()).sum()
    }

    /// Count total events across all sources
    pub fn total_events(&self) -> usize {
        self.get_sources().iter().map(|e| e.event_count).sum()
    }

    /// Get highest severity across all evidence
    fn max_severity(&self) -> u32 {
        self.get_sources()
            .iter()
            .map(|e| match e.severity.as_str() {
                "low" => 1,
                "medium" => 2,
                "high" => 3,
                _ => 0,
            })
            .max()
            .unwrap_or(0)
    }

    /// Get severity label from numeric value
    fn severity_label(level: u32) -> &'static str {
        match level {
            3 => "high",
            2 => "medium",
            _ => "low",
        }
    }

    /// Get overall case severity
    pub fn overall_severity(&self) -> String {
        Self::severity_label(self.max_severity()).to_string()
    }
}

impl Default for EvidenceBundle {
    fn default() -> Self {
        Self::new()
    }
}

/// A complete case file: agent event + all evidence + verdict + metadata
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CaseFile {
    pub case_id: String,
    pub timestamp: String,
    pub session_id: Option<String>,
    pub agent_event: AgentEvent,
    pub evidence: EvidenceBundle,
    pub verdict: Verdict,
    pub summary: String,
    pub tags: Vec<String>,
}

impl CaseFile {
    pub fn new(
        case_id: impl Into<String>,
        timestamp: impl Into<String>,
        agent_event: AgentEvent,
        verdict: Verdict,
    ) -> Self {
        let session = agent_event.session_id.clone();
        CaseFile {
            case_id: case_id.into(),
            timestamp: timestamp.into(),
            session_id: session,
            agent_event,
            evidence: EvidenceBundle::new(),
            verdict,
            summary: String::new(),
            tags: Vec::new(),
        }
    }

    /// Generate a summary from the evidence
    pub fn generate_summary(&mut self) {
        let sources = self.evidence.get_sources();
        let mut summary_parts = Vec::new();

        summary_parts.push(format!(
            "Case {}: {} verdict on tool '{}'",
            self.case_id,
            self.verdict_text(),
            self.agent_event.tool_name
        ));

        if !sources.is_empty() {
            summary_parts.push(format!("Evidence collected from {} sources", sources.len()));
            summary_parts.push(format!(
                "Total findings: {}",
                self.evidence.total_findings()
            ));
            summary_parts.push(format!(
                "Overall severity: {}",
                self.evidence.overall_severity()
            ));

            for source in sources {
                if !source.findings.is_empty() {
                    summary_parts.push(format!(
                        "  {} ({} findings, {})",
                        source.phase,
                        source.findings.len(),
                        source.severity
                    ));
                }
            }
        } else {
            summary_parts.push("No evidence collected (clean execution)".to_string());
        }

        self.summary = summary_parts.join("\n");
    }

    /// Add a tag for categorizing the case
    pub fn add_tag(&mut self, tag: impl Into<String>) {
        self.tags.push(tag.into());
    }

    /// Get verdict as string
    fn verdict_text(&self) -> &str {
        match self.verdict {
            Verdict::Allow => "ALLOW",
            Verdict::Ask => "ASK",
            Verdict::Deny => "DENY",
        }
    }

    /// Check if case has high-risk evidence
    pub fn has_high_risk(&self) -> bool {
        self.evidence
            .get_sources()
            .iter()
            .any(|e| e.severity == "high")
    }

    /// Get all findings from high-severity evidence
    pub fn get_high_risk_findings(&self) -> Vec<&str> {
        self.evidence
            .get_sources()
            .iter()
            .filter(|e| e.severity == "high")
            .flat_map(|e| e.findings.iter().map(|f| f.as_str()))
            .collect()
    }

    /// Get evidence count by phase
    pub fn evidence_count(&self) -> HashMap<String, usize> {
        let mut counts = HashMap::new();
        for source in self.evidence.get_sources() {
            counts.insert(source.phase.clone(), source.findings.len());
        }
        counts
    }
}

/// Case archive: collection of cases for analysis
#[derive(Debug, Clone)]
pub struct CaseArchive {
    cases: Vec<CaseFile>,
}

impl CaseArchive {
    pub fn new() -> Self {
        CaseArchive { cases: Vec::new() }
    }

    /// Add a case to the archive
    pub fn add_case(&mut self, case: CaseFile) {
        self.cases.push(case);
    }

    /// Get a case by ID
    pub fn get_case(&self, case_id: &str) -> Option<&CaseFile> {
        self.cases.iter().find(|c| c.case_id == case_id)
    }

    /// Get all cases
    pub fn get_all_cases(&self) -> &[CaseFile] {
        &self.cases
    }

    /// Get cases with a specific verdict
    pub fn get_by_verdict(&self, verdict: Verdict) -> Vec<&CaseFile> {
        self.cases.iter().filter(|c| c.verdict == verdict).collect()
    }

    /// Get cases with a specific tag
    pub fn get_by_tag(&self, tag: &str) -> Vec<&CaseFile> {
        self.cases
            .iter()
            .filter(|c| c.tags.iter().any(|t| t == tag))
            .collect()
    }

    /// Get high-risk cases
    pub fn get_high_risk_cases(&self) -> Vec<&CaseFile> {
        self.cases.iter().filter(|c| c.has_high_risk()).collect()
    }

    /// Count cases by verdict
    pub fn verdict_summary(&self) -> HashMap<String, usize> {
        let mut summary = HashMap::new();
        summary.insert("allow".to_string(), 0);
        summary.insert("ask".to_string(), 0);
        summary.insert("deny".to_string(), 0);

        for case in &self.cases {
            let key = match case.verdict {
                Verdict::Allow => "allow",
                Verdict::Ask => "ask",
                Verdict::Deny => "deny",
            };
            *summary.entry(key.to_string()).or_insert(0) += 1;
        }

        summary
    }

    /// Total cases in archive
    pub fn case_count(&self) -> usize {
        self.cases.len()
    }
}

impl Default for CaseArchive {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn create_test_event() -> AgentEvent {
        AgentEvent {
            hook_event_name: "PreToolUse".to_string(),
            timestamp: "2026-10-20T15:00:00Z".to_string(),
            session_id: Some("test_session".to_string()),
            user_id: Some("test_user".to_string()),
            tool_name: "bash".to_string(),
            tool_input: serde_json::json!({"command": "ls"}),
            context: Default::default(),
        }
    }

    #[test]
    fn test_sensor_evidence_creation() {
        let evidence = SensorEvidence::new("D1");
        assert_eq!(evidence.phase, "D1");
        assert!(evidence.findings.is_empty());
    }

    #[test]
    fn test_sensor_evidence_add_finding() {
        let mut evidence = SensorEvidence::new("D2");
        evidence.add_finding("Process privilege escalation detected");
        assert_eq!(evidence.findings.len(), 1);
    }

    #[test]
    fn test_evidence_bundle_new() {
        let bundle = EvidenceBundle::new();
        assert_eq!(bundle.total_findings(), 0);
        assert_eq!(bundle.total_events(), 0);
    }

    #[test]
    fn test_evidence_bundle_add_sources() {
        let mut bundle = EvidenceBundle::new();
        let mut d1 = SensorEvidence::new("D1");
        d1.add_finding("Execution detected");
        d1.event_count = 5;

        bundle.add_exec_evidence(d1);
        assert_eq!(bundle.total_findings(), 1);
        assert_eq!(bundle.total_events(), 5);
    }

    #[test]
    fn test_evidence_bundle_get_sources() {
        let mut bundle = EvidenceBundle::new();
        let mut d1 = SensorEvidence::new("D1");
        d1.add_finding("Event 1");
        let mut d3 = SensorEvidence::new("D3");
        d3.add_finding("Event 2");

        bundle.add_exec_evidence(d1);
        bundle.add_syscall_evidence(d3);

        assert_eq!(bundle.get_sources().len(), 2);
    }

    #[test]
    fn test_evidence_severity_high() {
        let mut evidence = SensorEvidence::new("D4");
        evidence.set_severity("high");
        assert_eq!(evidence.severity, "high");
    }

    #[test]
    fn test_evidence_bundle_overall_severity() {
        let mut bundle = EvidenceBundle::new();
        let mut low = SensorEvidence::new("D1");
        low.set_severity("low");
        let mut high = SensorEvidence::new("D4");
        high.set_severity("high");

        bundle.add_exec_evidence(low);
        bundle.add_egress_evidence(high);

        assert_eq!(bundle.overall_severity(), "high");
    }

    #[test]
    fn test_case_file_creation() {
        let event = create_test_event();
        let case = CaseFile::new("case_001", "2026-10-20T15:00:00Z", event, Verdict::Allow);

        assert_eq!(case.case_id, "case_001");
        assert_eq!(case.verdict, Verdict::Allow);
    }

    #[test]
    fn test_case_file_tags() {
        let event = create_test_event();
        let mut case = CaseFile::new("case_002", "2026-10-20T15:00:00Z", event, Verdict::Ask);
        case.add_tag("suspicious");
        case.add_tag("injection_attempt");

        assert_eq!(case.tags.len(), 2);
        assert!(case.tags.contains(&"suspicious".to_string()));
    }

    #[test]
    fn test_case_file_generate_summary() {
        let event = create_test_event();
        let mut case = CaseFile::new("case_003", "2026-10-20T15:00:00Z", event, Verdict::Deny);
        case.generate_summary();

        assert!(!case.summary.is_empty());
        assert!(case.summary.contains("DENY"));
    }

    #[test]
    fn test_case_file_has_high_risk() {
        let event = create_test_event();
        let mut case = CaseFile::new("case_004", "2026-10-20T15:00:00Z", event, Verdict::Deny);
        let mut evidence = SensorEvidence::new("D4");
        evidence.set_severity("high");
        evidence.add_finding("Data exfiltration detected");
        case.evidence.add_egress_evidence(evidence);

        assert!(case.has_high_risk());
    }

    #[test]
    fn test_case_file_get_high_risk_findings() {
        let event = create_test_event();
        let mut case = CaseFile::new("case_005", "2026-10-20T15:00:00Z", event, Verdict::Deny);
        let mut evidence = SensorEvidence::new("D3");
        evidence.set_severity("high");
        evidence.add_finding("Attempted /etc/shadow access");
        case.evidence.add_syscall_evidence(evidence);

        let findings = case.get_high_risk_findings();
        assert_eq!(findings.len(), 1);
    }

    #[test]
    fn test_archive_add_case() {
        let mut archive = CaseArchive::new();
        let event = create_test_event();
        let case = CaseFile::new("case_006", "2026-10-20T15:00:00Z", event, Verdict::Allow);

        archive.add_case(case);
        assert_eq!(archive.case_count(), 1);
    }

    #[test]
    fn test_archive_get_case() {
        let mut archive = CaseArchive::new();
        let event = create_test_event();
        let case = CaseFile::new("case_007", "2026-10-20T15:00:00Z", event, Verdict::Allow);

        archive.add_case(case);
        assert!(archive.get_case("case_007").is_some());
        assert!(archive.get_case("nonexistent").is_none());
    }

    #[test]
    fn test_archive_get_by_verdict() {
        let mut archive = CaseArchive::new();
        let event1 = create_test_event();
        let event2 = create_test_event();

        archive.add_case(CaseFile::new(
            "case_008",
            "2026-10-20T15:00:00Z",
            event1,
            Verdict::Allow,
        ));
        archive.add_case(CaseFile::new(
            "case_009",
            "2026-10-20T15:00:00Z",
            event2,
            Verdict::Deny,
        ));

        assert_eq!(archive.get_by_verdict(Verdict::Allow).len(), 1);
        assert_eq!(archive.get_by_verdict(Verdict::Deny).len(), 1);
    }

    #[test]
    fn test_archive_get_by_tag() {
        let mut archive = CaseArchive::new();
        let event = create_test_event();
        let mut case = CaseFile::new("case_010", "2026-10-20T15:00:00Z", event, Verdict::Ask);
        case.add_tag("malware");
        case.add_tag("c2");

        archive.add_case(case);
        let malware_cases = archive.get_by_tag("malware");

        assert_eq!(malware_cases.len(), 1);
    }

    #[test]
    fn test_archive_verdict_summary() {
        let mut archive = CaseArchive::new();
        let e1 = create_test_event();
        let e2 = create_test_event();
        let e3 = create_test_event();

        archive.add_case(CaseFile::new(
            "c1",
            "2026-10-20T15:00:00Z",
            e1,
            Verdict::Allow,
        ));
        archive.add_case(CaseFile::new(
            "c2",
            "2026-10-20T15:00:00Z",
            e2,
            Verdict::Ask,
        ));
        archive.add_case(CaseFile::new(
            "c3",
            "2026-10-20T15:00:00Z",
            e3,
            Verdict::Deny,
        ));

        let summary = archive.verdict_summary();
        assert_eq!(summary["allow"], 1);
        assert_eq!(summary["ask"], 1);
        assert_eq!(summary["deny"], 1);
    }

    #[test]
    fn test_archive_get_high_risk_cases() {
        let mut archive = CaseArchive::new();
        let event1 = create_test_event();
        let mut case1 = CaseFile::new("case_011", "2026-10-20T15:00:00Z", event1, Verdict::Deny);
        let mut evidence = SensorEvidence::new("D5");
        evidence.set_severity("high");
        case1.evidence.add_risk_evidence(evidence);

        let event2 = create_test_event();
        let case2 = CaseFile::new("case_012", "2026-10-20T15:00:00Z", event2, Verdict::Allow);

        archive.add_case(case1);
        archive.add_case(case2);

        assert_eq!(archive.get_high_risk_cases().len(), 1);
    }

    #[test]
    fn test_case_file_evidence_count() {
        let event = create_test_event();
        let mut case = CaseFile::new("case_013", "2026-10-20T15:00:00Z", event, Verdict::Ask);
        let mut d1 = SensorEvidence::new("D1");
        d1.add_finding("f1");
        d1.add_finding("f2");
        case.evidence.add_exec_evidence(d1);

        let counts = case.evidence_count();
        assert_eq!(counts["D1"], 2);
    }

    #[test]
    fn test_case_file_verdict_text() {
        let event = create_test_event();
        let case = CaseFile::new("case_014", "2026-10-20T15:00:00Z", event, Verdict::Deny);
        assert_eq!(case.verdict_text(), "DENY");
    }

    #[test]
    fn test_archive_empty() {
        let archive = CaseArchive::new();
        assert_eq!(archive.case_count(), 0);
        assert!(archive.get_all_cases().is_empty());
    }
}
