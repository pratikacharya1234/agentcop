//! Detective v1: analyzes case files and identifies suspicious patterns
//!
//! PLAN:
//! 1. Define AttackPattern enum: exfiltration, privilege escalation, c2, injection, etc.
//! 2. Define Finding: pattern name, confidence (0-100), evidence from which phases
//! 3. Define DetectiveReport: findings + risk summary + recommendations
//! 4. Implement pattern matching across case evidence
//! 5. Score confidence based on corroborating evidence

use cop_case::CaseFile;
use cop_core::Verdict;
use serde::{Deserialize, Serialize};

/// Attack patterns the detective can identify
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum AttackPattern {
    DataExfiltration,
    PrivilegeEscalation,
    CommandControl,
    ProcessInjection,
    CredentialAccess,
    DefenseEvasion,
    LateralMovement,
    Unknown,
}

impl AttackPattern {
    pub fn name(&self) -> &str {
        match self {
            AttackPattern::DataExfiltration => "Data Exfiltration",
            AttackPattern::PrivilegeEscalation => "Privilege Escalation",
            AttackPattern::CommandControl => "Command & Control",
            AttackPattern::ProcessInjection => "Process Injection",
            AttackPattern::CredentialAccess => "Credential Access",
            AttackPattern::DefenseEvasion => "Defense Evasion",
            AttackPattern::LateralMovement => "Lateral Movement",
            AttackPattern::Unknown => "Unknown Behavior",
        }
    }

    pub fn description(&self) -> &str {
        match self {
            AttackPattern::DataExfiltration => "Large data transfers to external hosts",
            AttackPattern::PrivilegeEscalation => "Process gained higher privileges than parent",
            AttackPattern::CommandControl => "Connection to suspicious ports or reverse shell",
            AttackPattern::ProcessInjection => "Orphaned process or unusual family chain",
            AttackPattern::CredentialAccess => "Access to sensitive files containing credentials",
            AttackPattern::DefenseEvasion => "Log deletion or syscall anomalies",
            AttackPattern::LateralMovement => "SSH to private networks with default credentials",
            AttackPattern::Unknown => "Suspicious behavior not matching known patterns",
        }
    }
}

/// A single finding from the detective's analysis
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Finding {
    pub pattern: AttackPattern,
    pub confidence: u32,               // 0-100
    pub evidence_sources: Vec<String>, // which phases provided evidence
    pub reasoning: String,
}

/// Recommendation for handling the case
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Recommendation {
    pub action: String,   // "block", "quarantine", "monitor", "allow"
    pub priority: String, // "critical", "high", "medium", "low"
    pub rationale: String,
    pub followup: String, // suggested next steps
}

/// Complete detective report for a case
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DetectiveReport {
    pub case_id: String,
    pub findings: Vec<Finding>,
    pub primary_pattern: Option<AttackPattern>,
    pub overall_risk: u32, // 0-100
    pub recommendation: Recommendation,
    pub summary: String,
}

pub struct Detective;

impl Detective {
    /// Analyze a case and produce a detective report
    pub fn investigate(case: &CaseFile) -> DetectiveReport {
        let mut findings = Vec::new();
        let mut risk_sum: u32 = 0;

        // Check for data exfiltration (D4 evidence)
        if let Some(egress) = &case.evidence.egress_evidence {
            if egress.severity == "high" {
                findings.push(Finding {
                    pattern: AttackPattern::DataExfiltration,
                    confidence: 95,
                    evidence_sources: vec!["D4".to_string()],
                    reasoning: "Egress monitor detected suspicious data transfer patterns"
                        .to_string(),
                });
                risk_sum += 80;
            }
        }

        // Check for privilege escalation (D2 + D5 evidence)
        if let Some(family) = &case.evidence.family_evidence {
            if family.severity == "high" {
                findings.push(Finding {
                    pattern: AttackPattern::PrivilegeEscalation,
                    confidence: 90,
                    evidence_sources: vec!["D2".to_string(), "D5".to_string()],
                    reasoning: "Family tree analysis shows privilege escalation pattern"
                        .to_string(),
                });
                risk_sum += 75;
            }
        }

        // Check for C2 communication (D4 + D3 evidence)
        if let Some(egress) = &case.evidence.egress_evidence {
            for finding in &egress.findings {
                if finding.contains("reverse") || finding.contains("C2") {
                    findings.push(Finding {
                        pattern: AttackPattern::CommandControl,
                        confidence: 85,
                        evidence_sources: vec!["D3".to_string(), "D4".to_string()],
                        reasoning: "Suspicious port connections and egress patterns indicate C2"
                            .to_string(),
                    });
                    risk_sum += 90;
                }
            }
        }

        // Check for credential access (D3 evidence)
        if let Some(syscall) = &case.evidence.syscall_evidence {
            if syscall
                .findings
                .iter()
                .any(|f| f.contains("shadow") || f.contains("ssh"))
            {
                findings.push(Finding {
                    pattern: AttackPattern::CredentialAccess,
                    confidence: 88,
                    evidence_sources: vec!["D3".to_string()],
                    reasoning:
                        "File syscalls show access to credential storage (/etc/shadow, ~/.ssh)"
                            .to_string(),
                });
                risk_sum += 70;
            }
        }

        // Check for process injection (D2 evidence)
        if let Some(family) = &case.evidence.family_evidence {
            if family
                .findings
                .iter()
                .any(|f| f.contains("orphan") || f.contains("chain"))
            {
                findings.push(Finding {
                    pattern: AttackPattern::ProcessInjection,
                    confidence: 75,
                    evidence_sources: vec!["D2".to_string()],
                    reasoning: "Process family analysis indicates potential injection".to_string(),
                });
                risk_sum += 60;
            }
        }

        // Check for defense evasion (D3 + D1 evidence)
        if let Some(syscall) = &case.evidence.syscall_evidence {
            if syscall.findings.iter().any(|f| f.contains("log")) {
                findings.push(Finding {
                    pattern: AttackPattern::DefenseEvasion,
                    confidence: 92,
                    evidence_sources: vec!["D3".to_string()],
                    reasoning: "Log deletion detected in syscall events".to_string(),
                });
                risk_sum += 85;
            }
        }

        risk_sum = risk_sum.min(100);

        let primary_pattern = findings.first().map(|f| f.pattern);

        let recommendation = Self::recommend(&case.verdict, risk_sum, &findings);
        let summary = Self::summarize(&case.case_id, &findings, risk_sum);

        DetectiveReport {
            case_id: case.case_id.clone(),
            findings,
            primary_pattern,
            overall_risk: risk_sum,
            recommendation,
            summary,
        }
    }

    /// Generate recommendation based on verdict and risk
    fn recommend(verdict: &Verdict, risk: u32, findings: &[Finding]) -> Recommendation {
        match (verdict, risk) {
            (Verdict::Deny, _) => Recommendation {
                action: "block".to_string(),
                priority: "critical".to_string(),
                rationale: "Verdict already DENY; enforce immediately".to_string(),
                followup: "Investigate process tree and associated accounts".to_string(),
            },
            (_, 80..=100) => Recommendation {
                action: "quarantine".to_string(),
                priority: "critical".to_string(),
                rationale: format!(
                    "High risk ({}) detected with {} patterns",
                    risk,
                    findings.len()
                ),
                followup: "Isolate process; collect forensics; review recent activity".to_string(),
            },
            (_, 60..=79) => Recommendation {
                action: "monitor".to_string(),
                priority: "high".to_string(),
                rationale: format!("Elevated risk ({}) warrants close observation", risk),
                followup: "Alert security team; prepare rollback plan".to_string(),
            },
            (Verdict::Ask, 30..=59) => Recommendation {
                action: "review".to_string(),
                priority: "medium".to_string(),
                rationale: format!("Medium risk ({}) requires human review", risk),
                followup: "Human reviewer should approve or deny based on context".to_string(),
            },
            _ => Recommendation {
                action: "allow".to_string(),
                priority: "low".to_string(),
                rationale: "Low risk; standard execution allowed".to_string(),
                followup: "Continue monitoring for anomalies".to_string(),
            },
        }
    }

    /// Generate human-readable summary
    fn summarize(case_id: &str, findings: &[Finding], risk: u32) -> String {
        let mut summary = format!("Case {}: Risk Level {} (", case_id, risk);

        summary.push_str(if risk >= 80 {
            "CRITICAL"
        } else if risk >= 60 {
            "HIGH"
        } else if risk >= 30 {
            "MEDIUM"
        } else {
            "LOW"
        });

        summary.push_str(")\n");

        if findings.is_empty() {
            summary.push_str("No suspicious patterns detected.");
        } else {
            summary.push_str(&format!("Identified {} pattern(s):\n", findings.len()));
            for finding in findings {
                summary.push_str(&format!(
                    "  • {} (confidence: {}%)\n",
                    finding.pattern.name(),
                    finding.confidence
                ));
            }
        }

        summary
    }

    /// Get confidence-weighted threat assessment
    pub fn threat_level(overall_risk: u32) -> &'static str {
        match overall_risk {
            80..=100 => "CRITICAL",
            60..=79 => "HIGH",
            40..=59 => "MEDIUM",
            20..=39 => "LOW",
            _ => "MINIMAL",
        }
    }

    /// Correlate findings to identify compound threats
    pub fn correlate_findings(findings: &[Finding]) -> Option<String> {
        let patterns: Vec<_> = findings.iter().map(|f| f.pattern).collect();

        if patterns.contains(&AttackPattern::PrivilegeEscalation)
            && patterns.contains(&AttackPattern::CredentialAccess)
        {
            return Some(
                "Privilege escalation + credential access suggests account compromise".to_string(),
            );
        }

        if patterns.contains(&AttackPattern::CommandControl)
            && patterns.contains(&AttackPattern::DataExfiltration)
        {
            return Some(
                "C2 + exfiltration suggests active breach; immediate containment required"
                    .to_string(),
            );
        }

        if patterns.contains(&AttackPattern::DefenseEvasion)
            && patterns.contains(&AttackPattern::ProcessInjection)
        {
            return Some(
                "Defense evasion + injection indicates sophisticated adversary tactics".to_string(),
            );
        }

        None
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use cop_case::{CaseFile, SensorEvidence};
    use cop_core::AgentEvent;

    fn create_test_case(verdict: Verdict) -> CaseFile {
        let event = AgentEvent {
            hook_type: "PreToolUse".to_string(),
            timestamp: "2026-10-20T16:00:00Z".to_string(),
            session_id: Some("test".to_string()),
            user_id: None,
            tool_name: "bash".to_string(),
            tool_input: serde_json::json!({}),
            context: Default::default(),
        };
        CaseFile::new("case_test", "2026-10-20T16:00:00Z", event, verdict)
    }

    #[test]
    fn test_attack_pattern_names() {
        assert_eq!(AttackPattern::DataExfiltration.name(), "Data Exfiltration");
        assert_eq!(
            AttackPattern::PrivilegeEscalation.name(),
            "Privilege Escalation"
        );
    }

    #[test]
    fn test_finding_creation() {
        let finding = Finding {
            pattern: AttackPattern::DataExfiltration,
            confidence: 95,
            evidence_sources: vec!["D4".to_string()],
            reasoning: "Test".to_string(),
        };
        assert_eq!(finding.confidence, 95);
    }

    #[test]
    fn test_detective_clean_case() {
        let case = create_test_case(Verdict::Allow);
        let report = Detective::investigate(&case);

        assert_eq!(report.case_id, "case_test");
        assert_eq!(report.findings.len(), 0);
    }

    #[test]
    fn test_detective_high_risk_case() {
        let mut case = create_test_case(Verdict::Deny);
        let mut egress = SensorEvidence::new("D4");
        egress.set_severity("high");
        egress.add_finding("reverse shell detected");
        case.evidence.add_egress_evidence(egress);

        let report = Detective::investigate(&case);

        assert!(!report.findings.is_empty());
        assert!(report.overall_risk > 50);
    }

    #[test]
    fn test_recommendation_deny_verdict() {
        let finding = Finding {
            pattern: AttackPattern::DataExfiltration,
            confidence: 90,
            evidence_sources: vec!["D4".to_string()],
            reasoning: "Test".to_string(),
        };

        let rec = Detective::recommend(&Verdict::Deny, 50, &[finding]);
        assert_eq!(rec.action, "block");
        assert_eq!(rec.priority, "critical");
    }

    #[test]
    fn test_recommendation_high_risk() {
        let rec = Detective::recommend(&Verdict::Ask, 85, &[]);
        assert_eq!(rec.action, "quarantine");
        assert_eq!(rec.priority, "critical");
    }

    #[test]
    fn test_recommendation_medium_risk() {
        let rec = Detective::recommend(&Verdict::Ask, 65, &[]);
        assert_eq!(rec.action, "monitor");
        assert_eq!(rec.priority, "high");
    }

    #[test]
    fn test_recommendation_low_risk() {
        let rec = Detective::recommend(&Verdict::Allow, 15, &[]);
        assert_eq!(rec.action, "allow");
    }

    #[test]
    fn test_threat_level_critical() {
        assert_eq!(Detective::threat_level(90), "CRITICAL");
    }

    #[test]
    fn test_threat_level_high() {
        assert_eq!(Detective::threat_level(70), "HIGH");
    }

    #[test]
    fn test_threat_level_medium() {
        assert_eq!(Detective::threat_level(45), "MEDIUM");
    }

    #[test]
    fn test_threat_level_low() {
        assert_eq!(Detective::threat_level(25), "LOW");
    }

    #[test]
    fn test_threat_level_minimal() {
        assert_eq!(Detective::threat_level(5), "MINIMAL");
    }

    #[test]
    fn test_report_summary_generation() {
        let mut case = create_test_case(Verdict::Ask);
        let mut egress = SensorEvidence::new("D4");
        egress.set_severity("high");
        egress.add_finding("exfiltration");
        case.evidence.add_egress_evidence(egress);

        let report = Detective::investigate(&case);
        assert!(!report.summary.is_empty());
    }

    #[test]
    fn test_correlate_privilege_and_credential() {
        let findings = vec![
            Finding {
                pattern: AttackPattern::PrivilegeEscalation,
                confidence: 90,
                evidence_sources: vec!["D2".to_string()],
                reasoning: "Test".to_string(),
            },
            Finding {
                pattern: AttackPattern::CredentialAccess,
                confidence: 88,
                evidence_sources: vec!["D3".to_string()],
                reasoning: "Test".to_string(),
            },
        ];

        let correlation = Detective::correlate_findings(&findings);
        assert!(correlation.is_some());
        assert!(correlation.unwrap().contains("account compromise"));
    }

    #[test]
    fn test_correlate_c2_and_exfiltration() {
        let findings = vec![
            Finding {
                pattern: AttackPattern::CommandControl,
                confidence: 85,
                evidence_sources: vec!["D4".to_string()],
                reasoning: "Test".to_string(),
            },
            Finding {
                pattern: AttackPattern::DataExfiltration,
                confidence: 95,
                evidence_sources: vec!["D4".to_string()],
                reasoning: "Test".to_string(),
            },
        ];

        let correlation = Detective::correlate_findings(&findings);
        assert!(correlation.is_some());
        assert!(correlation.unwrap().contains("active breach"));
    }

    #[test]
    fn test_correlate_evasion_and_injection() {
        let findings = vec![
            Finding {
                pattern: AttackPattern::DefenseEvasion,
                confidence: 92,
                evidence_sources: vec!["D3".to_string()],
                reasoning: "Test".to_string(),
            },
            Finding {
                pattern: AttackPattern::ProcessInjection,
                confidence: 75,
                evidence_sources: vec!["D2".to_string()],
                reasoning: "Test".to_string(),
            },
        ];

        let correlation = Detective::correlate_findings(&findings);
        assert!(correlation.is_some());
        assert!(correlation.unwrap().contains("sophisticated"));
    }

    #[test]
    fn test_detective_report_has_primary_pattern() {
        let mut case = create_test_case(Verdict::Deny);
        let mut egress = SensorEvidence::new("D4");
        egress.set_severity("high");
        egress.add_finding("data exfiltration");
        case.evidence.add_egress_evidence(egress);

        let report = Detective::investigate(&case);
        assert!(report.primary_pattern.is_some());
    }

    #[test]
    fn test_attack_pattern_descriptions() {
        assert!(!AttackPattern::DataExfiltration.description().is_empty());
        assert!(!AttackPattern::CommandControl.description().is_empty());
    }

    #[test]
    fn test_recommendation_structures() {
        let rec = Detective::recommend(&Verdict::Ask, 50, &[]);
        assert!(!rec.action.is_empty());
        assert!(!rec.priority.is_empty());
        assert!(!rec.rationale.is_empty());
        assert!(!rec.followup.is_empty());
    }

    #[test]
    fn test_multiple_patterns_same_case() {
        let mut case = create_test_case(Verdict::Deny);

        let mut egress = SensorEvidence::new("D4");
        egress.set_severity("high");
        egress.add_finding("reverse shell");
        case.evidence.add_egress_evidence(egress);

        let mut family = SensorEvidence::new("D2");
        family.set_severity("high");
        family.add_finding("privilege escalation");
        case.evidence.add_family_evidence(family);

        let report = Detective::investigate(&case);
        assert!(report.findings.len() >= 2);
    }
}
