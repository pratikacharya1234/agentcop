//! Courtroom: user-facing verdict presentation and appeal interfaces
//!
//! PLAN:
//! 1. Define VerdictDisplay: format verdict for end users
//! 2. Define AppealForm: structured appeal submission UI
//! 3. Define ComplianceDashboard: summary reporting for admins
//! 4. Generate formatted messages: verdict explanations, next steps
//! 5. Provide templates: email, Slack, dashboard views

use cop_affairs::ComplianceAudit;
use cop_case::CaseFile;
use cop_core::Verdict;
use cop_detective::DetectiveReport;
use serde::{Deserialize, Serialize};

/// How to display a verdict to the user
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VerdictDisplay {
    pub verdict: Verdict,
    pub title: String,           // "Blocked", "Allowed", "Under Review"
    pub description: String,     // human-readable explanation
    pub reason: String,          // why this decision was made
    pub next_steps: Vec<String>, // what user should do
    pub contact: String,         // who to contact for appeals
    pub severity_icon: String,   // emoji or icon for UI
}

impl VerdictDisplay {
    pub fn new(verdict: Verdict) -> Self {
        let (title, description, severity_icon) = match verdict {
            Verdict::Allow => (
                "Execution Allowed".to_string(),
                "Your request has been reviewed and approved for execution.".to_string(),
                "✅".to_string(),
            ),
            Verdict::Ask => (
                "Under Review".to_string(),
                "Your request is currently under security review.".to_string(),
                "⏳".to_string(),
            ),
            Verdict::Deny => (
                "Execution Blocked".to_string(),
                "This request has been blocked for security reasons.".to_string(),
                "🚫".to_string(),
            ),
        };

        VerdictDisplay {
            verdict,
            title,
            description,
            reason: String::new(),
            next_steps: Vec::new(),
            contact: "security@yourorg.com".to_string(),
            severity_icon,
        }
    }

    pub fn with_reason(mut self, reason: impl Into<String>) -> Self {
        self.reason = reason.into();
        self
    }

    pub fn with_next_steps(mut self, steps: Vec<String>) -> Self {
        self.next_steps = steps;
        self
    }

    pub fn with_contact(mut self, contact: impl Into<String>) -> Self {
        self.contact = contact.into();
        self
    }

    /// Format for email or text display
    pub fn format_message(&self) -> String {
        let mut msg = format!("{} {}\n\n", self.severity_icon, self.title);
        msg.push_str(&self.description);
        msg.push_str("\n\n");

        if !self.reason.is_empty() {
            msg.push_str("Why: ");
            msg.push_str(&self.reason);
            msg.push_str("\n\n");
        }

        if !self.next_steps.is_empty() {
            msg.push_str("Next steps:\n");
            for (i, step) in self.next_steps.iter().enumerate() {
                msg.push_str(&format!("{}. {}\n", i + 1, step));
            }
            msg.push('\n');
        }

        msg.push_str(&format!("Questions? Contact: {}", self.contact));
        msg
    }
}

/// Appeal form for users to contest a decision
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AppealForm {
    pub case_id: String,
    pub name: String,
    pub email: String,
    pub reason: String,
    pub supporting_info: String,
    pub submitted_at: String,
    pub status: String, // "draft", "submitted", "under_review", "approved", "denied"
}

impl AppealForm {
    pub fn new(case_id: impl Into<String>, email: impl Into<String>) -> Self {
        AppealForm {
            case_id: case_id.into(),
            name: String::new(),
            email: email.into(),
            reason: String::new(),
            supporting_info: String::new(),
            submitted_at: String::new(),
            status: "draft".to_string(),
        }
    }

    pub fn with_name(mut self, name: impl Into<String>) -> Self {
        self.name = name.into();
        self
    }

    pub fn with_reason(mut self, reason: impl Into<String>) -> Self {
        self.reason = reason.into();
        self
    }

    pub fn with_supporting_info(mut self, info: impl Into<String>) -> Self {
        self.supporting_info = info.into();
        self
    }

    pub fn submit(mut self, timestamp: impl Into<String>) -> Self {
        self.submitted_at = timestamp.into();
        self.status = "submitted".to_string();
        self
    }

    pub fn is_valid(&self) -> bool {
        !self.email.is_empty() && !self.reason.is_empty() && self.status != "draft"
    }
}

/// Compliance dashboard for admins
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ComplianceDashboard {
    pub period: String, // "daily", "weekly", "monthly"
    pub total_decisions: usize,
    pub approved: usize,
    pub denied: usize,
    pub under_review: usize,
    pub appeals_submitted: usize,
    pub appeals_approved: usize,
    pub compliance_rate: u32,
    pub key_findings: Vec<String>,
    pub recommendations: Vec<String>,
}

impl ComplianceDashboard {
    pub fn new(period: impl Into<String>) -> Self {
        ComplianceDashboard {
            period: period.into(),
            total_decisions: 0,
            approved: 0,
            denied: 0,
            under_review: 0,
            appeals_submitted: 0,
            appeals_approved: 0,
            compliance_rate: 100,
            key_findings: Vec::new(),
            recommendations: Vec::new(),
        }
    }

    pub fn add_finding(mut self, finding: impl Into<String>) -> Self {
        self.key_findings.push(finding.into());
        self
    }

    pub fn add_recommendation(mut self, rec: impl Into<String>) -> Self {
        self.recommendations.push(rec.into());
        self
    }

    pub fn html_report(&self) -> String {
        let mut html = format!("<h2>Compliance Dashboard - {}</h2>\n", self.period);

        html.push_str("<div class='metrics'>\n");
        html.push_str(&format!(
            "  <p>Total Decisions: {}</p>\n",
            self.total_decisions
        ));
        html.push_str(&format!("  <p>Approved: {}</p>\n", self.approved));
        html.push_str(&format!("  <p>Denied: {}</p>\n", self.denied));
        html.push_str(&format!(
            "  <p>Compliance Rate: {}%</p>\n",
            self.compliance_rate
        ));
        html.push_str("</div>\n");

        if !self.key_findings.is_empty() {
            html.push_str("<h3>Key Findings</h3>\n<ul>\n");
            for finding in &self.key_findings {
                html.push_str(&format!("  <li>{}</li>\n", finding));
            }
            html.push_str("</ul>\n");
        }

        if !self.recommendations.is_empty() {
            html.push_str("<h3>Recommendations</h3>\n<ul>\n");
            for rec in &self.recommendations {
                html.push_str(&format!("  <li>{}</li>\n", rec));
            }
            html.push_str("</ul>\n");
        }

        html
    }
}

pub struct Courtroom;

impl Courtroom {
    /// Create a verdict display from a case file and detective report
    pub fn present_verdict(case: &CaseFile, report: &DetectiveReport) -> VerdictDisplay {
        let mut display = VerdictDisplay::new(case.verdict);

        display = display.with_reason(case.evidence.overall_severity());

        match case.verdict {
            Verdict::Allow => {
                display.next_steps = vec![
                    "Your request has been approved".to_string(),
                    "Execution will proceed normally".to_string(),
                ];
            }
            Verdict::Ask => {
                display.next_steps = vec![
                    "Your request is under security review".to_string(),
                    "Expected decision within 24 hours".to_string(),
                    "An appeal can be submitted if you disagree with the decision".to_string(),
                ];
            }
            Verdict::Deny => {
                let findings = report
                    .findings
                    .iter()
                    .take(3)
                    .map(|f| format!("  • {}", f.pattern.name()))
                    .collect::<Vec<_>>()
                    .join("\n");

                display = display.with_reason(format!(
                    "The following security concerns were identified:\n{}",
                    findings
                ));

                display.next_steps = vec![
                    "Contact security team for more details".to_string(),
                    "Submit an appeal if you believe this is incorrect".to_string(),
                    "Review and remediate the identified issues".to_string(),
                ];
            }
        }

        display
    }

    /// Generate a user-friendly summary
    pub fn summary_for_user(case: &CaseFile) -> String {
        let mut summary = String::new();

        summary.push_str("Case Summary\n");
        summary.push_str("============\n\n");
        summary.push_str(&format!("Case ID: {}\n", case.case_id));
        summary.push_str(&format!("Tool: {}\n", case.agent_event.tool_name));
        summary.push_str(&format!("Verdict: {:?}\n\n", case.verdict));

        summary.push_str("Findings:\n");
        let sources = case.evidence.get_sources();
        if sources.is_empty() {
            summary.push_str("  No issues detected\n");
        } else {
            for source in sources {
                summary.push_str(&format!(
                    "  {} ({}): {}\n",
                    source.phase,
                    source.severity,
                    source.findings.len()
                ));
            }
        }

        summary
    }

    /// Generate admin-friendly audit summary
    pub fn audit_summary(audit: &ComplianceAudit) -> String {
        let stats = audit.stats();
        format!(
            "Compliance Audit Summary\n{}\nNon-Compliant Cases: {}",
            stats.summary(),
            audit.get_non_compliant().len()
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_verdict_display_allowed() {
        let display = VerdictDisplay::new(Verdict::Allow);
        assert_eq!(display.verdict, Verdict::Allow);
        assert!(display.title.contains("Allow"));
    }

    #[test]
    fn test_verdict_display_denied() {
        let display = VerdictDisplay::new(Verdict::Deny);
        assert_eq!(display.verdict, Verdict::Deny);
        assert!(display.title.contains("Block"));
    }

    #[test]
    fn test_verdict_display_format_message() {
        let display = VerdictDisplay::new(Verdict::Allow)
            .with_reason("All checks passed")
            .with_next_steps(vec!["Proceed".to_string()]);

        let msg = display.format_message();
        assert!(msg.contains("Allowed"));
        assert!(msg.contains("All checks passed"));
        assert!(msg.contains("Proceed"));
    }

    #[test]
    fn test_appeal_form_creation() {
        let form = AppealForm::new("case_001", "user@example.com");
        assert_eq!(form.case_id, "case_001");
        assert_eq!(form.status, "draft");
    }

    #[test]
    fn test_appeal_form_builder() {
        let form = AppealForm::new("case_001", "user@example.com")
            .with_name("John Doe")
            .with_reason("False positive");

        assert_eq!(form.name, "John Doe");
        assert_eq!(form.reason, "False positive");
    }

    #[test]
    fn test_appeal_form_submit() {
        let form = AppealForm::new("case_001", "user@example.com")
            .with_reason("False positive")
            .submit("2026-10-20T18:00:00Z");

        assert_eq!(form.status, "submitted");
        assert!(form.is_valid());
    }

    #[test]
    fn test_appeal_form_invalid_draft() {
        let form = AppealForm::new("case_001", "user@example.com");
        assert!(!form.is_valid());
    }

    #[test]
    fn test_compliance_dashboard_creation() {
        let dashboard = ComplianceDashboard::new("daily");
        assert_eq!(dashboard.period, "daily");
        assert_eq!(dashboard.compliance_rate, 100);
    }

    #[test]
    fn test_compliance_dashboard_findings() {
        let dashboard = ComplianceDashboard::new("daily")
            .add_finding("No incidents this period")
            .add_recommendation("Continue current practices");

        assert_eq!(dashboard.key_findings.len(), 1);
        assert_eq!(dashboard.recommendations.len(), 1);
    }

    #[test]
    fn test_compliance_dashboard_html() {
        let dashboard = ComplianceDashboard::new("daily").add_finding("Test finding");

        let html = dashboard.html_report();
        assert!(html.contains("<h2>"));
        assert!(html.contains("Test finding"));
    }

    #[test]
    fn test_courtroom_audit_summary() {
        let audit = ComplianceAudit::new();
        let summary = Courtroom::audit_summary(&audit);
        assert!(summary.contains("Compliance Audit"));
    }

    #[test]
    fn test_verdict_display_severity_icon() {
        let allowed = VerdictDisplay::new(Verdict::Allow);
        assert_eq!(allowed.severity_icon, "✅");

        let denied = VerdictDisplay::new(Verdict::Deny);
        assert_eq!(denied.severity_icon, "🚫");

        let ask = VerdictDisplay::new(Verdict::Ask);
        assert_eq!(ask.severity_icon, "⏳");
    }

    #[test]
    fn test_verdict_display_with_contact() {
        let display = VerdictDisplay::new(Verdict::Allow).with_contact("admin@example.com");

        assert_eq!(display.contact, "admin@example.com");
        let msg = display.format_message();
        assert!(msg.contains("admin@example.com"));
    }

    #[test]
    fn test_appeal_form_supporting_info() {
        let form = AppealForm::new("case_001", "user@example.com")
            .with_supporting_info("Additional context here");

        assert_eq!(form.supporting_info, "Additional context here");
    }

    #[test]
    fn test_compliance_dashboard_metrics() {
        let mut dashboard = ComplianceDashboard::new("weekly");
        dashboard.total_decisions = 100;
        dashboard.approved = 85;
        dashboard.denied = 10;
        dashboard.under_review = 5;

        assert_eq!(dashboard.total_decisions, 100);
    }

    #[test]
    fn test_verdict_display_next_steps_order() {
        let display = VerdictDisplay::new(Verdict::Allow)
            .with_next_steps(vec!["Step 1".to_string(), "Step 2".to_string()]);

        let msg = display.format_message();
        let step1_pos = msg.find("Step 1").unwrap_or(0);
        let step2_pos = msg.find("Step 2").unwrap_or(0);
        assert!(step1_pos < step2_pos);
    }

    #[test]
    fn test_appeal_form_email_validation() {
        let form = AppealForm::new("case_001", "valid@example.com");
        assert!(!form.email.is_empty());
    }

    #[test]
    fn test_compliance_dashboard_period_types() {
        let daily = ComplianceDashboard::new("daily");
        assert_eq!(daily.period, "daily");

        let weekly = ComplianceDashboard::new("weekly");
        assert_eq!(weekly.period, "weekly");

        let monthly = ComplianceDashboard::new("monthly");
        assert_eq!(monthly.period, "monthly");
    }

    #[test]
    fn test_verdict_display_format_empty_reason() {
        let display = VerdictDisplay::new(Verdict::Allow);
        let msg = display.format_message();
        assert!(!msg.is_empty());
    }
}
