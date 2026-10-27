//! Codex: LLM bridge for verdict explanations
//!
//! PLAN:
//! 1. ExplanationRequest: verdict + context (code, policy)
//! 2. format_prompt(): convert to Claude-friendly message
//! 3. MockResponse: simulate LLM response (real API later)
//! 4. Tests: format prompt, parse response, missing context handled

use cop_core::{Case, Verdict};

/// Request for LLM explanation of a verdict
pub struct ExplanationRequest {
    pub case: Case,
    pub code_context: Option<String>,
    pub policy_rule: Option<String>,
}

impl ExplanationRequest {
    /// Create a new explanation request
    pub fn new(case: Case) -> Self {
        ExplanationRequest {
            case,
            code_context: None,
            policy_rule: None,
        }
    }

    /// Set code context for better explanation
    pub fn with_code(mut self, code: String) -> Self {
        self.code_context = Some(code);
        self
    }

    /// Set the policy rule that was triggered
    pub fn with_rule(mut self, rule: String) -> Self {
        self.policy_rule = Some(rule);
        self
    }

    /// Format as a prompt for Claude
    pub fn to_prompt(&self) -> String {
        let verdict_str = match self.case.verdict {
            Verdict::Allow => "ALLOWED",
            Verdict::Ask => "REQUIRES_APPROVAL",
            Verdict::Deny => "BLOCKED",
        };

        let mut prompt = format!(
            "Agent action analysis:\n\
             Tool: {}\n\
             Verdict: {}\n\
             Reason: {}\n\n",
            self.case.event.tool_name,
            verdict_str,
            self.case.reason.as_deref().unwrap_or("(no reason)")
        );

        if let Some(rule) = &self.policy_rule {
            prompt.push_str(&format!("Policy rule triggered: {}\n\n", rule));
        }

        if let Some(code) = &self.code_context {
            prompt.push_str(&format!("Agent code context:\n{}\n\n", code));
        }

        prompt.push_str(
            "Provide a brief explanation of why this action was taken, \
             and suggest what the user should do next.",
        );

        prompt
    }
}

/// Mock response from explanation service
pub struct Explanation {
    pub verdict: String,
    pub reason: String,
    pub suggestion: String,
}

impl Explanation {
    /// Parse a response string into an Explanation
    pub fn parse(response: &str) -> Result<Self, String> {
        // Simple parsing: expect lines starting with prefixes
        let lines: Vec<&str> = response.lines().collect();

        let mut explanation = Explanation {
            verdict: String::new(),
            reason: String::new(),
            suggestion: String::new(),
        };

        for line in lines {
            if line.starts_with("Verdict:") {
                explanation.verdict = line
                    .strip_prefix("Verdict:")
                    .unwrap_or("")
                    .trim()
                    .to_string();
            } else if line.starts_with("Reason:") {
                explanation.reason = line
                    .strip_prefix("Reason:")
                    .unwrap_or("")
                    .trim()
                    .to_string();
            } else if line.starts_with("Suggestion:") {
                explanation.suggestion = line
                    .strip_prefix("Suggestion:")
                    .unwrap_or("")
                    .trim()
                    .to_string();
            }
        }

        if explanation.verdict.is_empty() {
            return Err("No verdict found in response".to_string());
        }

        Ok(explanation)
    }

    /// Create a mock explanation (for testing without API)
    pub fn mock(verdict: &str, reason: &str, suggestion: &str) -> Self {
        Explanation {
            verdict: verdict.to_string(),
            reason: reason.to_string(),
            suggestion: suggestion.to_string(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use cop_core::AgentEvent;
    use std::collections::HashMap;

    fn sample_case() -> Case {
        Case {
            event: AgentEvent {
                hook_type: "PreToolUse".to_string(),
                timestamp: "2026-10-20T10:00:00Z".to_string(),
                session_id: Some("s123".to_string()),
                user_id: Some("u456".to_string()),
                tool_name: "bash".to_string(),
                tool_input: serde_json::json!({"command": "rm -rf /"}),
                context: HashMap::new(),
            },
            verdict: Verdict::Deny,
            evidence_hash: None,
            reason: Some("Dangerous rm command".to_string()),
        }
    }

    #[test]
    fn format_prompt_includes_verdict() {
        let case = sample_case();
        let request = ExplanationRequest::new(case);
        let prompt = request.to_prompt();

        assert!(prompt.contains("BLOCKED"));
        assert!(prompt.contains("bash"));
        assert!(prompt.contains("Dangerous rm command"));
    }

    #[test]
    fn format_prompt_with_code_context() {
        let case = sample_case();
        let request = ExplanationRequest::new(case).with_code("rm -rf /".to_string());
        let prompt = request.to_prompt();

        assert!(prompt.contains("Agent code context:"));
        assert!(prompt.contains("rm -rf /"));
    }

    #[test]
    fn format_prompt_with_policy_rule() {
        let case = sample_case();
        let request =
            ExplanationRequest::new(case).with_rule("deny rm -rf on important paths".to_string());
        let prompt = request.to_prompt();

        assert!(prompt.contains("Policy rule triggered:"));
        assert!(prompt.contains("deny rm -rf"));
    }

    #[test]
    fn format_allow_verdict() {
        let mut case = sample_case();
        case.verdict = Verdict::Allow;
        let request = ExplanationRequest::new(case);
        let prompt = request.to_prompt();

        assert!(prompt.contains("ALLOWED"));
    }

    #[test]
    fn format_ask_verdict() {
        let mut case = sample_case();
        case.verdict = Verdict::Ask;
        let request = ExplanationRequest::new(case);
        let prompt = request.to_prompt();

        assert!(prompt.contains("REQUIRES_APPROVAL"));
    }

    #[test]
    fn parse_explanation_response() {
        let response = "Verdict: BLOCKED\nReason: Dangerous operation\nSuggestion: Review policy";
        let explanation = Explanation::parse(response).expect("Parse failed");

        assert_eq!(explanation.verdict, "BLOCKED");
        assert_eq!(explanation.reason, "Dangerous operation");
        assert_eq!(explanation.suggestion, "Review policy");
    }

    #[test]
    fn parse_explanation_missing_verdict_returns_error() {
        let response = "Reason: Some reason\nSuggestion: Do something";
        let result = Explanation::parse(response);

        assert!(result.is_err());
    }

    #[test]
    fn parse_explanation_partial_response() {
        let response = "Verdict: ALLOWED\nReason: Safe command";
        let explanation = Explanation::parse(response).expect("Parse failed");

        assert_eq!(explanation.verdict, "ALLOWED");
        assert_eq!(explanation.reason, "Safe command");
        assert!(explanation.suggestion.is_empty()); // Missing suggestion is OK
    }

    #[test]
    fn mock_explanation_for_testing() {
        let explanation = Explanation::mock("BLOCKED", "Test reason", "Test suggestion");

        assert_eq!(explanation.verdict, "BLOCKED");
        assert_eq!(explanation.reason, "Test reason");
        assert_eq!(explanation.suggestion, "Test suggestion");
    }
}
