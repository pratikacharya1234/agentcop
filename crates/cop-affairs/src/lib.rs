//! Internal Affairs: enforcement tracking and compliance auditing
//!
//! PLAN:
//! 1. Define EnforcementAction: what was done (blocked, allowed, quarantined, etc.)
//! 2. Define ComplianceRecord: case + verdict + action + timestamp + auditor
//! 3. Track appeals: override requests with reason and approval
//! 4. Verify execution: did the verdict actually get enforced?
//! 5. Audit trail: immutable log of all decisions

use cop_core::Verdict;
use serde::{Deserialize, Serialize};

/// What action was taken to enforce a verdict
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum EnforcementAction {
    Allowed,
    Blocked,
    Quarantined,
    Monitored,
    Escalated,
    Appealed,
    Overridden,
    Pending,
}

impl EnforcementAction {
    pub fn description(&self) -> &str {
        match self {
            EnforcementAction::Allowed => "Execution allowed",
            EnforcementAction::Blocked => "Execution blocked",
            EnforcementAction::Quarantined => "Process isolated/quarantined",
            EnforcementAction::Monitored => "Enhanced monitoring enabled",
            EnforcementAction::Escalated => "Escalated to security team",
            EnforcementAction::Appealed => "Awaiting appeal decision",
            EnforcementAction::Overridden => "Human override applied",
            EnforcementAction::Pending => "Enforcement pending",
        }
    }
}

/// A request to override or appeal a verdict
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Appeal {
    pub case_id: String,
    pub requester: String,
    pub reason: String,
    pub timestamp: String,
    pub approved: bool,
    pub approver: Option<String>,
    pub approval_reason: Option<String>,
}

impl Appeal {
    pub fn new(
        case_id: impl Into<String>,
        requester: impl Into<String>,
        reason: impl Into<String>,
        timestamp: impl Into<String>,
    ) -> Self {
        Appeal {
            case_id: case_id.into(),
            requester: requester.into(),
            reason: reason.into(),
            timestamp: timestamp.into(),
            approved: false,
            approver: None,
            approval_reason: None,
        }
    }

    pub fn approve(mut self, approver: impl Into<String>, reason: impl Into<String>) -> Self {
        self.approved = true;
        self.approver = Some(approver.into());
        self.approval_reason = Some(reason.into());
        self
    }
}

/// Complete compliance record for a case decision
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ComplianceRecord {
    pub case_id: String,
    pub verdict: Verdict,
    pub action: EnforcementAction,
    pub timestamp: String,
    pub enforcer: String, // who/what enforced it
    pub executed: bool,   // was the action actually taken?
    pub execution_time: Option<String>,
    pub appeal: Option<Appeal>,
    pub notes: String,
}

impl ComplianceRecord {
    pub fn new(
        case_id: impl Into<String>,
        verdict: Verdict,
        action: EnforcementAction,
        timestamp: impl Into<String>,
        enforcer: impl Into<String>,
    ) -> Self {
        ComplianceRecord {
            case_id: case_id.into(),
            verdict,
            action,
            timestamp: timestamp.into(),
            enforcer: enforcer.into(),
            executed: false,
            execution_time: None,
            appeal: None,
            notes: String::new(),
        }
    }

    pub fn mark_executed(mut self, execution_time: impl Into<String>) -> Self {
        self.executed = true;
        self.execution_time = Some(execution_time.into());
        self
    }

    pub fn with_notes(mut self, notes: impl Into<String>) -> Self {
        self.notes = notes.into();
        self
    }

    pub fn with_appeal(mut self, appeal: Appeal) -> Self {
        self.appeal = Some(appeal);
        self
    }

    pub fn is_compliant(&self) -> bool {
        self.executed || matches!(self.action, EnforcementAction::Allowed)
    }
}

/// Compliance audit log: collection of all decisions
#[derive(Debug, Clone)]
pub struct ComplianceAudit {
    records: Vec<ComplianceRecord>,
}

impl ComplianceAudit {
    pub fn new() -> Self {
        ComplianceAudit {
            records: Vec::new(),
        }
    }

    /// Log a compliance record
    pub fn log_decision(&mut self, record: ComplianceRecord) {
        self.records.push(record);
    }

    /// Get a record by case ID
    pub fn get_record(&self, case_id: &str) -> Option<&ComplianceRecord> {
        self.records.iter().find(|r| r.case_id == case_id)
    }

    /// Get all records
    pub fn get_all_records(&self) -> &[ComplianceRecord] {
        &self.records
    }

    /// Get records by action type
    pub fn get_by_action(&self, action: EnforcementAction) -> Vec<&ComplianceRecord> {
        self.records.iter().filter(|r| r.action == action).collect()
    }

    /// Get records by verdict
    pub fn get_by_verdict(&self, verdict: Verdict) -> Vec<&ComplianceRecord> {
        self.records
            .iter()
            .filter(|r| r.verdict == verdict)
            .collect()
    }

    /// Get all non-compliant records (not executed when should have been)
    pub fn get_non_compliant(&self) -> Vec<&ComplianceRecord> {
        self.records.iter().filter(|r| !r.is_compliant()).collect()
    }

    /// Get all appealed cases
    pub fn get_appealed_cases(&self) -> Vec<&ComplianceRecord> {
        self.records.iter().filter(|r| r.appeal.is_some()).collect()
    }

    /// Get approved appeals
    pub fn get_approved_appeals(&self) -> Vec<&ComplianceRecord> {
        self.records
            .iter()
            .filter(|r| r.appeal.as_ref().map(|a| a.approved).unwrap_or(false))
            .collect()
    }

    /// Compliance statistics
    pub fn stats(&self) -> ComplianceStats {
        let total = self.records.len();
        let compliant = self.records.iter().filter(|r| r.is_compliant()).count();
        let non_compliant = total - compliant;
        let appealed = self.get_appealed_cases().len();
        let approved_appeals = self.get_approved_appeals().len();

        let blocked = self.get_by_action(EnforcementAction::Blocked).len();
        let allowed = self.get_by_action(EnforcementAction::Allowed).len();

        ComplianceStats {
            total_decisions: total,
            compliant_decisions: compliant,
            non_compliant_decisions: non_compliant,
            total_appeals: appealed,
            approved_appeals,
            blocked_count: blocked,
            allowed_count: allowed,
            compliance_rate: if total > 0 {
                (compliant as f32 / total as f32 * 100.0) as u32
            } else {
                100
            },
        }
    }

    /// Total records
    pub fn record_count(&self) -> usize {
        self.records.len()
    }
}

impl Default for ComplianceAudit {
    fn default() -> Self {
        Self::new()
    }
}

/// Compliance statistics summary
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ComplianceStats {
    pub total_decisions: usize,
    pub compliant_decisions: usize,
    pub non_compliant_decisions: usize,
    pub total_appeals: usize,
    pub approved_appeals: usize,
    pub blocked_count: usize,
    pub allowed_count: usize,
    pub compliance_rate: u32, // percentage
}

impl ComplianceStats {
    pub fn summary(&self) -> String {
        format!(
            "Compliance Report:\n  Total Decisions: {}\n  Compliant: {} ({:.0}%)\n  Non-Compliant: {}\n  Appeals: {} (approved: {})\n  Blocked: {}, Allowed: {}",
            self.total_decisions,
            self.compliant_decisions,
            self.compliance_rate,
            self.non_compliant_decisions,
            self.total_appeals,
            self.approved_appeals,
            self.blocked_count,
            self.allowed_count
        )
    }
}

pub struct InternalAffairs;

impl InternalAffairs {
    /// Verify that a verdict was actually enforced
    pub fn verify_enforcement(record: &ComplianceRecord) -> bool {
        match record.action {
            EnforcementAction::Allowed => !record.executed, // allowed = don't need to execute block
            EnforcementAction::Blocked => record.executed,
            EnforcementAction::Quarantined => record.executed,
            EnforcementAction::Monitored => record.executed,
            EnforcementAction::Escalated => record.executed,
            EnforcementAction::Appealed => !record.executed, // awaiting appeal result
            EnforcementAction::Overridden => record.executed,
            EnforcementAction::Pending => false, // still pending
        }
    }

    /// Approve an appeal
    pub fn approve_appeal(
        appeal: &mut Appeal,
        approver: impl Into<String>,
        reason: impl Into<String>,
    ) {
        appeal.approved = true;
        appeal.approver = Some(approver.into());
        appeal.approval_reason = Some(reason.into());
    }

    /// Check if enforcement chain is complete
    pub fn verify_chain_of_custody(audit: &ComplianceAudit) -> bool {
        audit.get_non_compliant().is_empty()
    }

    /// Get enforcement rate for a specific enforcer
    pub fn enforcer_compliance(audit: &ComplianceAudit, enforcer: &str) -> f32 {
        let records: Vec<_> = audit
            .get_all_records()
            .iter()
            .filter(|r| r.enforcer == enforcer)
            .collect();

        if records.is_empty() {
            return 100.0;
        }

        let compliant = records.iter().filter(|r| r.is_compliant()).count();
        (compliant as f32 / records.len() as f32) * 100.0
    }

    /// Generate audit summary
    pub fn audit_summary(audit: &ComplianceAudit) -> String {
        let stats = audit.stats();
        stats.summary()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_enforcement_action_descriptions() {
        assert!(!EnforcementAction::Blocked.description().is_empty());
        assert!(!EnforcementAction::Allowed.description().is_empty());
    }

    #[test]
    fn test_appeal_creation() {
        let appeal = Appeal::new("case_001", "user", "false positive", "2026-10-20T17:00:00Z");
        assert_eq!(appeal.case_id, "case_001");
        assert!(!appeal.approved);
    }

    #[test]
    fn test_appeal_approval() {
        let appeal = Appeal::new("case_001", "user", "reason", "2026-10-20T17:00:00Z")
            .approve("admin", "approved");
        assert!(appeal.approved);
        assert_eq!(appeal.approver, Some("admin".to_string()));
    }

    #[test]
    fn test_compliance_record_creation() {
        let record = ComplianceRecord::new(
            "case_001",
            Verdict::Deny,
            EnforcementAction::Blocked,
            "2026-10-20T17:00:00Z",
            "cop-enforcer",
        );

        assert_eq!(record.case_id, "case_001");
        assert_eq!(record.verdict, Verdict::Deny);
        assert!(!record.executed);
    }

    #[test]
    fn test_compliance_record_mark_executed() {
        let record = ComplianceRecord::new(
            "case_001",
            Verdict::Deny,
            EnforcementAction::Blocked,
            "2026-10-20T17:00:00Z",
            "cop",
        )
        .mark_executed("2026-10-20T17:00:05Z");

        assert!(record.executed);
        assert!(record.execution_time.is_some());
    }

    #[test]
    fn test_compliance_audit_log() {
        let mut audit = ComplianceAudit::new();
        let record = ComplianceRecord::new(
            "case_001",
            Verdict::Allow,
            EnforcementAction::Allowed,
            "2026-10-20T17:00:00Z",
            "cop",
        );

        audit.log_decision(record);
        assert_eq!(audit.record_count(), 1);
    }

    #[test]
    fn test_compliance_audit_get_record() {
        let mut audit = ComplianceAudit::new();
        let record = ComplianceRecord::new(
            "case_001",
            Verdict::Allow,
            EnforcementAction::Allowed,
            "2026-10-20T17:00:00Z",
            "cop",
        );

        audit.log_decision(record);
        assert!(audit.get_record("case_001").is_some());
        assert!(audit.get_record("nonexistent").is_none());
    }

    #[test]
    fn test_compliance_audit_by_action() {
        let mut audit = ComplianceAudit::new();
        audit.log_decision(ComplianceRecord::new(
            "case_001",
            Verdict::Deny,
            EnforcementAction::Blocked,
            "2026-10-20T17:00:00Z",
            "cop",
        ));
        audit.log_decision(ComplianceRecord::new(
            "case_002",
            Verdict::Allow,
            EnforcementAction::Allowed,
            "2026-10-20T17:00:00Z",
            "cop",
        ));

        let blocked = audit.get_by_action(EnforcementAction::Blocked);
        assert_eq!(blocked.len(), 1);
    }

    #[test]
    fn test_compliance_audit_by_verdict() {
        let mut audit = ComplianceAudit::new();
        audit.log_decision(ComplianceRecord::new(
            "case_001",
            Verdict::Deny,
            EnforcementAction::Blocked,
            "2026-10-20T17:00:00Z",
            "cop",
        ));
        audit.log_decision(ComplianceRecord::new(
            "case_002",
            Verdict::Deny,
            EnforcementAction::Blocked,
            "2026-10-20T17:00:00Z",
            "cop",
        ));

        let denies = audit.get_by_verdict(Verdict::Deny);
        assert_eq!(denies.len(), 2);
    }

    #[test]
    fn test_compliance_record_is_compliant() {
        let allowed = ComplianceRecord::new(
            "case_001",
            Verdict::Allow,
            EnforcementAction::Allowed,
            "2026-10-20T17:00:00Z",
            "cop",
        );
        assert!(allowed.is_compliant());

        let blocked_but_not_executed = ComplianceRecord::new(
            "case_002",
            Verdict::Deny,
            EnforcementAction::Blocked,
            "2026-10-20T17:00:00Z",
            "cop",
        );
        assert!(!blocked_but_not_executed.is_compliant());

        let blocked_and_executed = ComplianceRecord::new(
            "case_003",
            Verdict::Deny,
            EnforcementAction::Blocked,
            "2026-10-20T17:00:00Z",
            "cop",
        )
        .mark_executed("2026-10-20T17:00:05Z");
        assert!(blocked_and_executed.is_compliant());
    }

    #[test]
    fn test_compliance_stats() {
        let mut audit = ComplianceAudit::new();
        audit.log_decision(ComplianceRecord::new(
            "case_001",
            Verdict::Allow,
            EnforcementAction::Allowed,
            "2026-10-20T17:00:00Z",
            "cop",
        ));
        audit.log_decision(
            ComplianceRecord::new(
                "case_002",
                Verdict::Deny,
                EnforcementAction::Blocked,
                "2026-10-20T17:00:00Z",
                "cop",
            )
            .mark_executed("2026-10-20T17:00:05Z"),
        );

        let stats = audit.stats();
        assert_eq!(stats.total_decisions, 2);
        assert_eq!(stats.compliant_decisions, 2);
        assert_eq!(stats.compliance_rate, 100);
    }

    #[test]
    fn test_appealed_cases() {
        let mut audit = ComplianceAudit::new();
        let appeal = Appeal::new("case_001", "user", "reason", "2026-10-20T17:00:00Z");
        let record = ComplianceRecord::new(
            "case_001",
            Verdict::Deny,
            EnforcementAction::Blocked,
            "2026-10-20T17:00:00Z",
            "cop",
        )
        .with_appeal(appeal);

        audit.log_decision(record);
        assert_eq!(audit.get_appealed_cases().len(), 1);
    }

    #[test]
    fn test_approved_appeals() {
        let mut audit = ComplianceAudit::new();
        let appeal = Appeal::new("case_001", "user", "reason", "2026-10-20T17:00:00Z")
            .approve("admin", "approved");
        let record = ComplianceRecord::new(
            "case_001",
            Verdict::Deny,
            EnforcementAction::Blocked,
            "2026-10-20T17:00:00Z",
            "cop",
        )
        .with_appeal(appeal);

        audit.log_decision(record);
        assert_eq!(audit.get_approved_appeals().len(), 1);
    }

    #[test]
    fn test_verify_enforcement() {
        let allowed = ComplianceRecord::new(
            "case_001",
            Verdict::Allow,
            EnforcementAction::Allowed,
            "2026-10-20T17:00:00Z",
            "cop",
        );
        assert!(InternalAffairs::verify_enforcement(&allowed));

        let blocked_executed = ComplianceRecord::new(
            "case_002",
            Verdict::Deny,
            EnforcementAction::Blocked,
            "2026-10-20T17:00:00Z",
            "cop",
        )
        .mark_executed("2026-10-20T17:00:05Z");
        assert!(InternalAffairs::verify_enforcement(&blocked_executed));
    }

    #[test]
    fn test_verify_chain_of_custody() {
        let mut audit = ComplianceAudit::new();
        audit.log_decision(ComplianceRecord::new(
            "case_001",
            Verdict::Allow,
            EnforcementAction::Allowed,
            "2026-10-20T17:00:00Z",
            "cop",
        ));

        assert!(InternalAffairs::verify_chain_of_custody(&audit));
    }

    #[test]
    fn test_enforcer_compliance() {
        let mut audit = ComplianceAudit::new();
        audit.log_decision(ComplianceRecord::new(
            "case_001",
            Verdict::Allow,
            EnforcementAction::Allowed,
            "2026-10-20T17:00:00Z",
            "enforcer_a",
        ));

        let rate = InternalAffairs::enforcer_compliance(&audit, "enforcer_a");
        assert_eq!(rate, 100.0);
    }

    #[test]
    fn test_audit_summary() {
        let mut audit = ComplianceAudit::new();
        audit.log_decision(ComplianceRecord::new(
            "case_001",
            Verdict::Allow,
            EnforcementAction::Allowed,
            "2026-10-20T17:00:00Z",
            "cop",
        ));

        let summary = InternalAffairs::audit_summary(&audit);
        assert!(summary.contains("Compliance Report"));
    }

    #[test]
    fn test_non_compliant_records() {
        let mut audit = ComplianceAudit::new();
        audit.log_decision(ComplianceRecord::new(
            "case_001",
            Verdict::Deny,
            EnforcementAction::Blocked,
            "2026-10-20T17:00:00Z",
            "cop",
        )); // not executed

        let non_compliant = audit.get_non_compliant();
        assert_eq!(non_compliant.len(), 1);
    }

    #[test]
    fn test_compliance_record_with_notes() {
        let record = ComplianceRecord::new(
            "case_001",
            Verdict::Deny,
            EnforcementAction::Blocked,
            "2026-10-20T17:00:00Z",
            "cop",
        )
        .with_notes("Blocked due to exfiltration attempt");

        assert_eq!(record.notes, "Blocked due to exfiltration attempt");
    }

    #[test]
    fn test_stats_compliance_rate() {
        let mut audit = ComplianceAudit::new();
        for i in 0..10 {
            if i % 2 == 0 {
                audit.log_decision(ComplianceRecord::new(
                    format!("case_{:03}", i),
                    Verdict::Allow,
                    EnforcementAction::Allowed,
                    "2026-10-20T17:00:00Z",
                    "cop",
                ));
            } else {
                audit.log_decision(
                    ComplianceRecord::new(
                        format!("case_{:03}", i),
                        Verdict::Deny,
                        EnforcementAction::Blocked,
                        "2026-10-20T17:00:00Z",
                        "cop",
                    )
                    .mark_executed("2026-10-20T17:00:05Z"),
                );
            }
        }

        let stats = audit.stats();
        assert_eq!(stats.compliance_rate, 100);
    }

    #[test]
    fn test_empty_audit() {
        let audit = ComplianceAudit::new();
        let stats = audit.stats();
        assert_eq!(stats.total_decisions, 0);
        assert_eq!(stats.compliance_rate, 100);
    }
}
