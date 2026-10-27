//! Fix suggestions: generates remediation plans based on detective findings
//!
//! PLAN:
//! 1. Define RemediationStep: action, command, expected outcome, validation
//! 2. Define RemediationPlan: ordered steps with priority and effort estimate
//! 3. Map patterns to fixes: privilege escalation → drop perms, exfil → network rules, etc.
//! 4. Validation: tests to verify fixes prevent re-occurrence
//! 5. Risk scoring: complexity vs. security gain trade-offs

use cop_detective::{AttackPattern, DetectiveReport, Finding};
use serde::{Deserialize, Serialize};

/// A single remediation action
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RemediationStep {
    pub order: u32,
    pub title: String,
    pub description: String,
    pub action: String,          // code change, config, rule, etc.
    pub command: Option<String>, // shell command or code snippet
    pub validation: String,      // how to test this step
    pub effort: u32,             // 1-5 complexity scale
}

impl RemediationStep {
    pub fn new(order: u32, title: impl Into<String>, description: impl Into<String>) -> Self {
        RemediationStep {
            order,
            title: title.into(),
            description: description.into(),
            action: String::new(),
            command: None,
            validation: String::new(),
            effort: 2,
        }
    }

    pub fn with_action(mut self, action: impl Into<String>) -> Self {
        self.action = action.into();
        self
    }

    pub fn with_command(mut self, command: impl Into<String>) -> Self {
        self.command = Some(command.into());
        self
    }

    pub fn with_validation(mut self, validation: impl Into<String>) -> Self {
        self.validation = validation.into();
        self
    }

    pub fn with_effort(mut self, effort: u32) -> Self {
        self.effort = effort.min(5);
        self
    }
}

/// Complete remediation plan for a case
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RemediationPlan {
    pub case_id: String,
    pub primary_threat: String,
    pub severity: String, // critical, high, medium, low
    pub steps: Vec<RemediationStep>,
    pub total_effort: u32,
    pub estimated_mitigation_time_minutes: u32,
    pub follow_up_actions: Vec<String>,
}

impl RemediationPlan {
    pub fn new(case_id: impl Into<String>, threat: impl Into<String>) -> Self {
        RemediationPlan {
            case_id: case_id.into(),
            primary_threat: threat.into(),
            severity: "medium".to_string(),
            steps: Vec::new(),
            total_effort: 0,
            estimated_mitigation_time_minutes: 0,
            follow_up_actions: Vec::new(),
        }
    }

    pub fn add_step(&mut self, step: RemediationStep) {
        self.total_effort += step.effort;
        self.estimated_mitigation_time_minutes += step.effort * 5; // 5 min per effort unit
        self.steps.push(step);
    }

    pub fn add_followup(&mut self, action: impl Into<String>) {
        self.follow_up_actions.push(action.into());
    }

    pub fn set_severity(&mut self, severity: &str) {
        self.severity = severity.to_string();
    }

    pub fn summary(&self) -> String {
        format!(
            "Remediation Plan for {}: {}\n  Severity: {}\n  Steps: {}\n  Estimated time: {} minutes\n  Total effort: {}",
            self.case_id,
            self.primary_threat,
            self.severity,
            self.steps.len(),
            self.estimated_mitigation_time_minutes,
            self.total_effort
        )
    }
}

pub struct Fixer;

impl Fixer {
    /// Generate a remediation plan from a detective report
    pub fn fix(report: &DetectiveReport) -> RemediationPlan {
        let threat = report
            .primary_pattern
            .map(|p| p.name().to_string())
            .unwrap_or_else(|| "Unknown".to_string());
        let mut plan = RemediationPlan::new(&report.case_id, threat);

        plan.set_severity(match report.overall_risk {
            80..=100 => "critical",
            60..=79 => "high",
            40..=59 => "medium",
            _ => "low",
        });

        for finding in &report.findings {
            Self::add_pattern_fixes(&mut plan, finding);
        }

        Self::add_general_hardening(&mut plan);

        plan
    }

    /// Add fixes specific to an attack pattern
    fn add_pattern_fixes(plan: &mut RemediationPlan, finding: &Finding) {
        match finding.pattern {
            AttackPattern::DataExfiltration => {
                plan.add_step(
                    RemediationStep::new(1, "Network Segmentation", "Isolate sensitive data")
                        .with_action(
                            "Add firewall rule to block large uploads on non-standard ports",
                        )
                        .with_command("sudo ufw deny out to any port 4444:9999")
                        .with_validation("Verify rule blocks test connections to C2 ports")
                        .with_effort(2),
                );

                plan.add_step(
                    RemediationStep::new(2, "DLP Policy", "Data loss prevention")
                        .with_action("Implement content-aware filtering")
                        .with_command("Enable log inspection for credential patterns")
                        .with_validation("Test with dummy credentials in HTTP body")
                        .with_effort(3),
                );
            }
            AttackPattern::PrivilegeEscalation => {
                plan.add_step(
                    RemediationStep::new(1, "Permission Model", "Enforce least privilege")
                        .with_action("Run agent processes with minimal required permissions")
                        .with_command("setcap -r /usr/bin/agent_binary # remove all capabilities")
                        .with_validation(
                            "Run agent and verify it cannot escalate via chmod or setuid",
                        )
                        .with_effort(2),
                );

                plan.add_step(
                    RemediationStep::new(2, "Process Isolation", "Restrict syscall surface")
                        .with_action("Apply seccomp profile to block privilege escalation syscalls")
                        .with_command("echo 'block mprotect' >> /etc/seccomp.json")
                        .with_validation("Run agent with profile; verify chmod/setuid blocked")
                        .with_effort(3),
                );
            }
            AttackPattern::CommandControl => {
                plan.add_step(
                    RemediationStep::new(1, "Port Blocking", "Block C2 communication")
                        .with_action("Add egress rules for all C2 ports")
                        .with_command(
                            "sudo iptables -A OUTPUT -p tcp -m multiport --dports 4444,5555,6666,7777,8888,9999,31337 -j DROP"
                        )
                        .with_validation("Agent should fail to connect to reverse shell port")
                        .with_effort(1),
                );

                plan.add_step(
                    RemediationStep::new(2, "DNS Filtering", "Block C2 domains")
                        .with_action("Add DNS block list for known C2 infrastructure")
                        .with_command("Add malware.badactor.com to /etc/hosts blocklist")
                        .with_validation("nslookup malware.badactor.com should fail")
                        .with_effort(2),
                );
            }
            AttackPattern::CredentialAccess => {
                plan.add_step(
                    RemediationStep::new(1, "File Permissions", "Lock down credential files")
                        .with_action("Restrict read access to sensitive files")
                        .with_command("chmod 600 ~/.ssh/id_rsa; chmod 400 /etc/shadow")
                        .with_validation("Agent should be unable to read files")
                        .with_effort(1),
                );

                plan.add_step(
                    RemediationStep::new(2, "Credential Rotation", "Refresh all credentials")
                        .with_action("Rotate SSH keys, API tokens, database passwords")
                        .with_command("ssh-keygen -f ~/.ssh/id_rsa -N ''")
                        .with_validation("Old credentials should not authenticate")
                        .with_effort(2),
                );
            }
            AttackPattern::DefenseEvasion => {
                plan.add_step(
                    RemediationStep::new(1, "Immutable Logs", "Prevent log tampering")
                        .with_action("Configure append-only log file protection")
                        .with_command("chattr +a /var/log/auth.log")
                        .with_validation("Verify rm or truncate on log file fails")
                        .with_effort(1),
                );

                plan.add_step(
                    RemediationStep::new(2, "Audit Logs", "Ship logs remotely")
                        .with_action("Forward logs to SIEM outside agent's control")
                        .with_command("echo '@reboot logger -t agentcop' >> crontab")
                        .with_validation("Logs persisted offhost even if onhost logs deleted")
                        .with_effort(3),
                );
            }
            AttackPattern::ProcessInjection => {
                plan.add_step(
                    RemediationStep::new(1, "Process Hardening", "Prevent code injection")
                        .with_action("Use code signing and integrity verification")
                        .with_command("echo 'verify_signature(agent_binary)' in startup script")
                        .with_validation("Modified agent binary should fail signature check")
                        .with_effort(3),
                );

                plan.add_step(
                    RemediationStep::new(2, "Memory Protection", "Disable code execution")
                        .with_action("Use NX bit and ASLR")
                        .with_command("echo 'ASLR enabled' in kernel boot flags")
                        .with_validation("ROP chains and shellcode should fail")
                        .with_effort(2),
                );
            }
            _ => {
                plan.add_step(
                    RemediationStep::new(1, "Generic Hardening", "Apply standard controls")
                        .with_action("Enable monitoring and alerting")
                        .with_command("enable_auditd; enable_osquery;")
                        .with_validation("Anomalies detected in logs within 1 minute")
                        .with_effort(2),
                );
            }
        }
    }

    /// Add general hardening steps applicable to all cases
    fn add_general_hardening(plan: &mut RemediationPlan) {
        let step_num = (plan.steps.len() + 1) as u32;

        plan.add_step(
            RemediationStep::new(step_num, "Monitoring", "Enable continuous monitoring")
                .with_action("Activate agent behavior monitoring")
                .with_command("systemctl enable agent-monitor")
                .with_validation("Monitor alerts on first suspicious syscall")
                .with_effort(2),
        );

        plan.add_followup("Review and update threat model");
        plan.add_followup("Conduct security training for development team");
        plan.add_followup("Schedule 30-day re-assessment");
    }

    /// Estimate time to implement all fixes
    pub fn time_estimate(plan: &RemediationPlan) -> String {
        let hours = plan.estimated_mitigation_time_minutes / 60;
        let minutes = plan.estimated_mitigation_time_minutes % 60;
        format!("{}h {}m", hours, minutes)
    }

    /// Get quick-win fixes (effort <= 2)
    pub fn quick_wins(plan: &RemediationPlan) -> Vec<&RemediationStep> {
        plan.steps.iter().filter(|s| s.effort <= 2).collect()
    }

    /// Get complex fixes (effort >= 4)
    pub fn complex_fixes(plan: &RemediationPlan) -> Vec<&RemediationStep> {
        plan.steps.iter().filter(|s| s.effort >= 4).collect()
    }

    /// Validate that a step is correctly specified
    pub fn validate_step(step: &RemediationStep) -> bool {
        !step.title.is_empty()
            && !step.description.is_empty()
            && !step.validation.is_empty()
            && step.effort > 0
            && step.effort <= 5
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use cop_detective::{DetectiveReport, Recommendation};

    fn create_test_report() -> DetectiveReport {
        DetectiveReport {
            case_id: "case_fix_test".to_string(),
            findings: vec![],
            primary_pattern: Some(AttackPattern::DataExfiltration),
            overall_risk: 85,
            recommendation: Recommendation {
                action: "quarantine".to_string(),
                priority: "critical".to_string(),
                rationale: "High risk".to_string(),
                followup: "Isolate".to_string(),
            },
            summary: "Test summary".to_string(),
        }
    }

    #[test]
    fn test_remediation_step_creation() {
        let step = RemediationStep::new(1, "Test", "Description");
        assert_eq!(step.order, 1);
        assert_eq!(step.title, "Test");
    }

    #[test]
    fn test_remediation_step_builder() {
        let step = RemediationStep::new(1, "Test", "Desc")
            .with_action("action")
            .with_command("cmd")
            .with_validation("validate")
            .with_effort(3);

        assert_eq!(step.action, "action");
        assert_eq!(step.command, Some("cmd".to_string()));
        assert_eq!(step.effort, 3);
    }

    #[test]
    fn test_remediation_plan_creation() {
        let plan = RemediationPlan::new("case_001", "Data Exfiltration");
        assert_eq!(plan.case_id, "case_001");
        assert_eq!(plan.steps.len(), 0);
    }

    #[test]
    fn test_remediation_plan_add_step() {
        let mut plan = RemediationPlan::new("case_001", "Test");
        let step = RemediationStep::new(1, "Step 1", "Description").with_effort(2);
        plan.add_step(step);

        assert_eq!(plan.steps.len(), 1);
        assert_eq!(plan.total_effort, 2);
    }

    #[test]
    fn test_fixer_generates_plan() {
        let report = create_test_report();
        let plan = Fixer::fix(&report);

        assert_eq!(plan.case_id, "case_fix_test");
        assert!(!plan.steps.is_empty());
    }

    #[test]
    fn test_fixer_data_exfiltration_pattern() {
        let mut report = create_test_report();
        report.primary_pattern = Some(AttackPattern::DataExfiltration);
        report.findings.push(Finding {
            pattern: AttackPattern::DataExfiltration,
            confidence: 95,
            evidence_sources: vec!["D4".to_string()],
            reasoning: "Test".to_string(),
        });
        let plan = Fixer::fix(&report);

        assert!(plan.steps.iter().any(|s| s.title.contains("Network")));
    }

    #[test]
    fn test_fixer_privilege_escalation_pattern() {
        let mut report = create_test_report();
        report.primary_pattern = Some(AttackPattern::PrivilegeEscalation);
        report.findings.push(Finding {
            pattern: AttackPattern::PrivilegeEscalation,
            confidence: 90,
            evidence_sources: vec!["D2".to_string()],
            reasoning: "Test".to_string(),
        });
        let plan = Fixer::fix(&report);

        assert!(plan.steps.iter().any(|s| s.title.contains("Permission")));
    }

    #[test]
    fn test_fixer_command_control_pattern() {
        let mut report = create_test_report();
        report.primary_pattern = Some(AttackPattern::CommandControl);
        report.findings.push(Finding {
            pattern: AttackPattern::CommandControl,
            confidence: 85,
            evidence_sources: vec!["D4".to_string()],
            reasoning: "Test".to_string(),
        });
        let plan = Fixer::fix(&report);

        assert!(plan.steps.iter().any(|s| s.title.contains("Port")));
    }

    #[test]
    fn test_fixer_credential_access_pattern() {
        let mut report = create_test_report();
        report.primary_pattern = Some(AttackPattern::CredentialAccess);
        report.findings.push(Finding {
            pattern: AttackPattern::CredentialAccess,
            confidence: 88,
            evidence_sources: vec!["D3".to_string()],
            reasoning: "Test".to_string(),
        });
        let plan = Fixer::fix(&report);

        assert!(plan.steps.iter().any(|s| s.title.contains("Permission")));
    }

    #[test]
    fn test_time_estimate() {
        let mut plan = RemediationPlan::new("case", "test");
        plan.estimated_mitigation_time_minutes = 90;
        let estimate = Fixer::time_estimate(&plan);
        assert!(estimate.contains("1h"));
    }

    #[test]
    fn test_quick_wins() {
        let mut plan = RemediationPlan::new("case", "test");
        plan.add_step(RemediationStep::new(1, "Quick", "desc").with_effort(1));
        plan.add_step(RemediationStep::new(2, "Complex", "desc").with_effort(4));

        let quick = Fixer::quick_wins(&plan);
        assert_eq!(quick.len(), 1);
        assert_eq!(quick[0].title, "Quick");
    }

    #[test]
    fn test_complex_fixes() {
        let mut plan = RemediationPlan::new("case", "test");
        plan.add_step(RemediationStep::new(1, "Quick", "desc").with_effort(1));
        plan.add_step(RemediationStep::new(2, "Complex", "desc").with_effort(4));

        let complex = Fixer::complex_fixes(&plan);
        assert_eq!(complex.len(), 1);
        assert_eq!(complex[0].title, "Complex");
    }

    #[test]
    fn test_validate_step() {
        let valid_step = RemediationStep::new(1, "Title", "Desc")
            .with_validation("validate")
            .with_effort(2);
        assert!(Fixer::validate_step(&valid_step));

        let invalid_step = RemediationStep::new(1, "", "Desc");
        assert!(!Fixer::validate_step(&invalid_step));
    }

    #[test]
    fn test_plan_summary() {
        let plan = RemediationPlan::new("case_001", "Test Threat");
        let summary = plan.summary();
        assert!(summary.contains("case_001"));
        assert!(summary.contains("Test Threat"));
    }

    #[test]
    fn test_plan_followup_actions() {
        let mut plan = RemediationPlan::new("case", "test");
        plan.add_followup("Action 1");
        plan.add_followup("Action 2");

        assert_eq!(plan.follow_up_actions.len(), 2);
    }

    #[test]
    fn test_plan_severity_critical() {
        let mut plan = RemediationPlan::new("case", "test");
        plan.set_severity("critical");
        assert_eq!(plan.severity, "critical");
    }

    #[test]
    fn test_fixer_adds_general_hardening() {
        let report = create_test_report();
        let plan = Fixer::fix(&report);

        assert!(plan.steps.iter().any(|s| s.title.contains("Monitor")));
    }

    #[test]
    fn test_defense_evasion_pattern() {
        let mut report = create_test_report();
        report.primary_pattern = Some(AttackPattern::DefenseEvasion);
        report.findings.push(Finding {
            pattern: AttackPattern::DefenseEvasion,
            confidence: 92,
            evidence_sources: vec!["D3".to_string()],
            reasoning: "Test".to_string(),
        });
        let plan = Fixer::fix(&report);

        assert!(plan.steps.iter().any(|s| s.title.contains("Immutable")));
    }

    #[test]
    fn test_effort_capped_at_5() {
        let step = RemediationStep::new(1, "Test", "Desc").with_effort(10);
        assert_eq!(step.effort, 5);
    }

    #[test]
    fn test_process_injection_pattern() {
        let mut report = create_test_report();
        report.primary_pattern = Some(AttackPattern::ProcessInjection);
        report.findings.push(Finding {
            pattern: AttackPattern::ProcessInjection,
            confidence: 75,
            evidence_sources: vec!["D2".to_string()],
            reasoning: "Test".to_string(),
        });
        let plan = Fixer::fix(&report);

        assert!(plan.steps.iter().any(|s| s.title.contains("Hardening")));
    }
}
