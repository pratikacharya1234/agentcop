//! Rule of Two: institutional governance requiring dual approval for critical actions
//!
//! PLAN:
//! 1. Define Approver: authorized signatories for critical decisions
//! 2. Define CriticalAction: policy changes, role changes, appeals, overrides
//! 3. Implement Rule of Two: require 2 independent approvals
//! 4. Track separation of duties: approver != requester
//! 5. Maintain governance log: immutable record of all critical decisions

use serde::{Deserialize, Serialize};

/// An authorized approver (role-based)
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum ApproverRole {
    SecurityOfficer,
    Auditor,
    TeamLead,
    Compliance,
    CTO,
}

impl ApproverRole {
    pub fn can_approve_override(&self) -> bool {
        matches!(self, ApproverRole::SecurityOfficer | ApproverRole::CTO)
    }

    pub fn can_approve_policy(&self) -> bool {
        matches!(
            self,
            ApproverRole::SecurityOfficer | ApproverRole::CTO | ApproverRole::Compliance
        )
    }

    pub fn can_approve_appeal(&self) -> bool {
        matches!(
            self,
            ApproverRole::Auditor | ApproverRole::SecurityOfficer | ApproverRole::TeamLead
        )
    }
}

/// A critical action that requires dual approval
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CriticalAction {
    pub action_id: String,
    pub action_type: String, // "override", "policy_change", "appeal_approval", "role_change"
    pub requested_by: String,
    pub requested_at: String,
    pub description: String,
    pub approvals: Vec<Approval>,
    pub status: String, // "pending", "approved", "rejected"
}

impl CriticalAction {
    pub fn new(
        action_id: impl Into<String>,
        action_type: impl Into<String>,
        requested_by: impl Into<String>,
        timestamp: impl Into<String>,
        description: impl Into<String>,
    ) -> Self {
        CriticalAction {
            action_id: action_id.into(),
            action_type: action_type.into(),
            requested_by: requested_by.into(),
            requested_at: timestamp.into(),
            description: description.into(),
            approvals: Vec::new(),
            status: "pending".to_string(),
        }
    }

    pub fn add_approval(&mut self, approval: Approval) -> bool {
        if self.approvals.len() >= 2 {
            return false; // Already has 2 approvals
        }

        // Separation of duties: approver must not be requester
        if approval.approver == self.requested_by {
            return false;
        }

        // No duplicate approvals from same person
        if self
            .approvals
            .iter()
            .any(|a| a.approver == approval.approver)
        {
            return false;
        }

        self.approvals.push(approval);

        // Check if we now have rule of two
        if self.approvals.len() == 2 && self.approvals.iter().all(|a| a.approved) {
            self.status = "approved".to_string();
        }

        true
    }

    pub fn is_approved(&self) -> bool {
        self.status == "approved" && self.approvals.len() == 2
    }

    pub fn is_pending(&self) -> bool {
        self.status == "pending"
    }
}

/// A single approval signature
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Approval {
    pub approver: String,
    pub role: String,
    pub approved: bool,
    pub timestamp: String,
    pub reason: String,
}

impl Approval {
    pub fn new(
        approver: impl Into<String>,
        role: impl Into<String>,
        timestamp: impl Into<String>,
    ) -> Self {
        Approval {
            approver: approver.into(),
            role: role.into(),
            approved: false,
            timestamp: timestamp.into(),
            reason: String::new(),
        }
    }

    pub fn approve(mut self, reason: impl Into<String>) -> Self {
        self.approved = true;
        self.reason = reason.into();
        self
    }

    pub fn reject(mut self, reason: impl Into<String>) -> Self {
        self.approved = false;
        self.reason = reason.into();
        self
    }
}

/// Governance policy
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GovernancePolicy {
    pub name: String,
    pub description: String,
    pub version: u32,
    pub effective_date: String,
    pub requires_dual_approval: bool,
    pub required_roles: Vec<String>,
}

impl GovernancePolicy {
    pub fn new(
        name: impl Into<String>,
        description: impl Into<String>,
        effective_date: impl Into<String>,
    ) -> Self {
        GovernancePolicy {
            name: name.into(),
            description: description.into(),
            version: 1,
            effective_date: effective_date.into(),
            requires_dual_approval: true,
            required_roles: Vec::new(),
        }
    }

    pub fn with_required_roles(mut self, roles: Vec<String>) -> Self {
        self.required_roles = roles;
        self
    }
}

/// Governance audit trail
#[derive(Debug, Clone)]
pub struct GovernanceLog {
    actions: Vec<CriticalAction>,
}

impl GovernanceLog {
    pub fn new() -> Self {
        GovernanceLog {
            actions: Vec::new(),
        }
    }

    pub fn log_action(&mut self, action: CriticalAction) {
        self.actions.push(action);
    }

    pub fn get_action(&self, action_id: &str) -> Option<&CriticalAction> {
        self.actions.iter().find(|a| a.action_id == action_id)
    }

    pub fn get_all_actions(&self) -> &[CriticalAction] {
        &self.actions
    }

    pub fn get_pending_actions(&self) -> Vec<&CriticalAction> {
        self.actions.iter().filter(|a| a.is_pending()).collect()
    }

    pub fn get_approved_actions(&self) -> Vec<&CriticalAction> {
        self.actions.iter().filter(|a| a.is_approved()).collect()
    }

    pub fn action_count(&self) -> usize {
        self.actions.len()
    }
}

impl Default for GovernanceLog {
    fn default() -> Self {
        Self::new()
    }
}

pub struct RuleOfTwo;

impl RuleOfTwo {
    /// Verify that an action has proper dual approval
    pub fn verify_approval(action: &CriticalAction) -> bool {
        action.is_approved()
            && action.approvals.len() == 2
            && action
                .approvals
                .iter()
                .all(|a| a.approved && !a.reason.is_empty())
    }

    /// Verify separation of duties
    pub fn verify_separation(action: &CriticalAction) -> bool {
        action
            .approvals
            .iter()
            .all(|a| a.approver != action.requested_by)
    }

    /// Verify role diversity
    pub fn verify_role_diversity(action: &CriticalAction) -> bool {
        if action.approvals.len() < 2 {
            return false;
        }

        let roles: Vec<_> = action.approvals.iter().map(|a| &a.role).collect();
        roles[0] != roles[1] // Different roles
    }

    /// Check if action has rule of two compliance
    pub fn has_rule_of_two(action: &CriticalAction) -> bool {
        Self::verify_approval(action)
            && Self::verify_separation(action)
            && Self::verify_role_diversity(action)
    }

    /// Generate governance report
    pub fn governance_report(log: &GovernanceLog) -> String {
        let total = log.action_count();
        let approved = log.get_approved_actions().len();
        let pending = log.get_pending_actions().len();

        format!(
            "Governance Report\nTotal Actions: {}\nApproved (Rule of Two): {}\nPending: {}",
            total, approved, pending
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_critical_action_creation() {
        let action = CriticalAction::new(
            "act_001",
            "override",
            "user@example.com",
            "2026-10-20T20:00:00Z",
            "Override suspicious action",
        );

        assert_eq!(action.action_id, "act_001");
        assert!(action.is_pending());
    }

    #[test]
    fn test_approval_creation() {
        let approval = Approval::new(
            "approver@example.com",
            "security_officer",
            "2026-10-20T20:00:00Z",
        );

        assert!(!approval.approved);
    }

    #[test]
    fn test_approval_approve() {
        let approval = Approval::new(
            "approver@example.com",
            "security_officer",
            "2026-10-20T20:00:00Z",
        )
        .approve("Verified legitimate");

        assert!(approval.approved);
        assert_eq!(approval.reason, "Verified legitimate");
    }

    #[test]
    fn test_critical_action_add_approval() {
        let mut action = CriticalAction::new(
            "act_001",
            "override",
            "user@example.com",
            "2026-10-20T20:00:00Z",
            "Test",
        );

        let approval = Approval::new("approver1@example.com", "security", "2026-10-20T20:00:01Z")
            .approve("OK");

        assert!(action.add_approval(approval));
        assert_eq!(action.approvals.len(), 1);
    }

    #[test]
    fn test_rule_of_two_requires_two_approvals() {
        let mut action = CriticalAction::new(
            "act_001",
            "override",
            "user@example.com",
            "2026-10-20T20:00:00Z",
            "Test",
        );

        let approval1 =
            Approval::new("approver1@example.com", "sec", "2026-10-20T20:00:01Z").approve("OK");
        let approval2 =
            Approval::new("approver2@example.com", "audit", "2026-10-20T20:00:02Z").approve("OK");

        action.add_approval(approval1);
        action.add_approval(approval2);

        assert!(RuleOfTwo::has_rule_of_two(&action));
    }

    #[test]
    fn test_separation_of_duties() {
        let mut action = CriticalAction::new(
            "act_001",
            "override",
            "user@example.com",
            "2026-10-20T20:00:00Z",
            "Test",
        );

        let approval = Approval::new("user@example.com", "security", "2026-10-20T20:00:01Z")
            .approve("Self-approval");

        // Should fail: requester can't approve their own action
        assert!(!action.add_approval(approval));
    }

    #[test]
    fn test_no_duplicate_approvers() {
        let mut action = CriticalAction::new(
            "act_001",
            "override",
            "user@example.com",
            "2026-10-20T20:00:00Z",
            "Test",
        );

        let approval1 =
            Approval::new("approver@example.com", "security", "2026-10-20T20:00:01Z").approve("OK");
        let approval2 =
            Approval::new("approver@example.com", "audit", "2026-10-20T20:00:02Z").approve("OK");

        action.add_approval(approval1);
        // Should fail: duplicate approver
        assert!(!action.add_approval(approval2));
    }

    #[test]
    fn test_governance_log_creation() {
        let log = GovernanceLog::new();
        assert_eq!(log.action_count(), 0);
    }

    #[test]
    fn test_governance_log_add_action() {
        let mut log = GovernanceLog::new();
        let action = CriticalAction::new(
            "act_001",
            "override",
            "user@example.com",
            "2026-10-20T20:00:00Z",
            "Test",
        );

        log.log_action(action);
        assert_eq!(log.action_count(), 1);
    }

    #[test]
    fn test_approver_role_permissions() {
        let sec_officer = ApproverRole::SecurityOfficer;
        assert!(sec_officer.can_approve_override());
        assert!(sec_officer.can_approve_policy());
        assert!(sec_officer.can_approve_appeal());
    }

    #[test]
    fn test_governance_policy_creation() {
        let policy = GovernancePolicy::new("Dual Approval", "Rule of two policy", "2026-10-20");
        assert_eq!(policy.name, "Dual Approval");
        assert!(policy.requires_dual_approval);
    }

    #[test]
    fn test_rule_of_two_verification() {
        let mut action = CriticalAction::new(
            "act_001",
            "override",
            "user@example.com",
            "2026-10-20T20:00:00Z",
            "Test",
        );

        let approval1 =
            Approval::new("approver1@example.com", "sec", "2026-10-20T20:00:01Z").approve("OK");
        let approval2 =
            Approval::new("approver2@example.com", "audit", "2026-10-20T20:00:02Z").approve("OK");

        action.add_approval(approval1);
        action.add_approval(approval2);

        assert!(RuleOfTwo::verify_approval(&action));
        assert!(RuleOfTwo::verify_separation(&action));
        assert!(RuleOfTwo::verify_role_diversity(&action));
    }

    #[test]
    fn test_get_pending_actions() {
        let mut log = GovernanceLog::new();
        let action1 = CriticalAction::new(
            "act_001",
            "override",
            "user@example.com",
            "2026-10-20T20:00:00Z",
            "Test1",
        );
        let mut action2 = CriticalAction::new(
            "act_002",
            "policy",
            "user@example.com",
            "2026-10-20T20:00:00Z",
            "Test2",
        );

        let approval1 =
            Approval::new("approver1@example.com", "sec", "2026-10-20T20:00:01Z").approve("OK");
        let approval2 =
            Approval::new("approver2@example.com", "audit", "2026-10-20T20:00:02Z").approve("OK");

        action2.add_approval(approval1);
        action2.add_approval(approval2);

        log.log_action(action1);
        log.log_action(action2);

        assert_eq!(log.get_pending_actions().len(), 1);
        assert_eq!(log.get_approved_actions().len(), 1);
    }

    #[test]
    fn test_governance_report() {
        let mut log = GovernanceLog::new();
        let action = CriticalAction::new(
            "act_001",
            "override",
            "user@example.com",
            "2026-10-20T20:00:00Z",
            "Test",
        );

        log.log_action(action);
        let report = RuleOfTwo::governance_report(&log);

        assert!(report.contains("Governance Report"));
        assert!(report.contains("1"));
    }

    #[test]
    fn test_action_max_two_approvals() {
        let mut action = CriticalAction::new(
            "act_001",
            "override",
            "user@example.com",
            "2026-10-20T20:00:00Z",
            "Test",
        );

        let approval1 =
            Approval::new("approver1@example.com", "sec", "2026-10-20T20:00:01Z").approve("OK");
        let approval2 =
            Approval::new("approver2@example.com", "audit", "2026-10-20T20:00:02Z").approve("OK");
        let approval3 = Approval::new(
            "approver3@example.com",
            "compliance",
            "2026-10-20T20:00:03Z",
        )
        .approve("OK");

        action.add_approval(approval1);
        action.add_approval(approval2);
        // Should fail: already has 2 approvals
        assert!(!action.add_approval(approval3));
    }

    #[test]
    fn test_governance_log_get_action() {
        let mut log = GovernanceLog::new();
        let action = CriticalAction::new(
            "act_001",
            "override",
            "user@example.com",
            "2026-10-20T20:00:00Z",
            "Test",
        );

        log.log_action(action);
        assert!(log.get_action("act_001").is_some());
        assert!(log.get_action("nonexistent").is_none());
    }

    #[test]
    fn test_approval_reject() {
        let approval = Approval::new("approver@example.com", "security", "2026-10-20T20:00:00Z")
            .reject("Security concern");

        assert!(!approval.approved);
        assert_eq!(approval.reason, "Security concern");
    }
}
