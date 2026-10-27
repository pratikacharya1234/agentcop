use cop_codex::ExplanationRequest;
use cop_core::{Case, Verdict};
use cop_evidence::EvidenceStore;
use cop_honeypot::HoneypotDetector;
use cop_logger::Logger;
use cop_normalizer::Normalizer;
use cop_policy::Judge;
use cop_ratelimit::{LimitChecker, RateLimitPolicy};
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PipelineResponse {
    pub verdict: String,
    pub reason: String,
    pub explanation: Option<String>,
    pub honeypot_alert: Option<String>,
    pub rate_limit_status: Option<String>,
}

pub struct LoggingPipeline {
    judge: Judge,
    honeypot: HoneypotDetector,
    rate_limit: LimitChecker,
    logger: Logger,
    evidence_store: Option<EvidenceStore>,
}

impl LoggingPipeline {
    pub fn new(judge: Judge, evidence_store: Option<EvidenceStore>) -> Self {
        LoggingPipeline {
            judge,
            honeypot: HoneypotDetector::new().expect("Failed to create honeypot detector"),
            rate_limit: LimitChecker::new(RateLimitPolicy::standard()),
            logger: Logger::new(10),
            evidence_store,
        }
    }

    pub fn process(&mut self, input: &str) -> Result<PipelineResponse, String> {
        // Step 1: Normalize sensor input to AgentEvent
        let event = Normalizer::from_json(input)?;

        // Step 2: Check honeypots (instant deny if triggered)
        let honeypot_alert = self.honeypot.check(&event);
        if honeypot_alert.is_some() {
            let reason = honeypot_alert.clone().unwrap_or_default();
            let verdict = Verdict::Deny;
            let case = Case {
                event: event.clone(),
                verdict,
                evidence_hash: None,
                reason: Some(reason.clone()),
            };

            if let Some(ref mut store) = self.evidence_store {
                let _ = store.append(&case);
            }

            return Ok(PipelineResponse {
                verdict: "deny".to_string(),
                reason,
                explanation: None,
                honeypot_alert: honeypot_alert.clone(),
                rate_limit_status: None,
            });
        }

        // Step 3: Check rate limits
        let user_id = event
            .user_id
            .clone()
            .unwrap_or_else(|| "unknown".to_string());
        let session_id = event
            .session_id
            .clone()
            .unwrap_or_else(|| "unknown".to_string());
        let rate_limit_exceeded = !self.rate_limit.check(&user_id, &session_id, &event);
        if rate_limit_exceeded {
            let reason = "Rate limit exceeded".to_string();
            let verdict = Verdict::Deny;
            let case = Case {
                event: event.clone(),
                verdict,
                evidence_hash: None,
                reason: Some(reason.clone()),
            };

            if let Some(ref mut store) = self.evidence_store {
                let _ = store.append(&case);
            }

            return Ok(PipelineResponse {
                verdict: "deny".to_string(),
                reason,
                explanation: None,
                honeypot_alert: None,
                rate_limit_status: Some("exceeded".to_string()),
            });
        }

        // Step 4: Judge the event
        let (verdict, judge_reason) = self.judge.judge(&event);
        let reason = judge_reason;

        // Step 5: Create case and store evidence
        let case = Case {
            event: event.clone(),
            verdict,
            evidence_hash: None,
            reason: Some(reason.clone()),
        };

        if let Some(ref mut store) = self.evidence_store {
            let _ = store.append(&case);
        }

        // Step 6: Generate explanation (optional)
        let explanation = ExplanationRequest::new(case.clone()).to_prompt();

        // Step 7: Format log entry (with rate limiting)
        let log_entry = self.logger.log(&case);
        let rate_limit_status = if log_entry.is_some() {
            Some("logged".to_string())
        } else {
            Some("rate_limited".to_string())
        };

        // Step 8: Return response
        let verdict_str = match verdict {
            Verdict::Allow => "allow".to_string(),
            Verdict::Ask => "ask".to_string(),
            Verdict::Deny => "deny".to_string(),
        };

        Ok(PipelineResponse {
            verdict: verdict_str,
            reason,
            explanation: Some(explanation),
            honeypot_alert: None,
            rate_limit_status,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn create_test_judge() -> Judge {
        let policy = cop_policy::Policy {
            mode: cop_policy::Mode::Enforce,
            rules: vec![
                cop_policy::Rule {
                    pattern: "rm.*-rf".to_string(),
                    scope: Some("bash".to_string()),
                    verdict: "deny".to_string(),
                    reason: Some("Destructive remove".to_string()),
                },
                cop_policy::Rule {
                    pattern: "git.*push".to_string(),
                    scope: Some("bash".to_string()),
                    verdict: "ask".to_string(),
                    reason: Some("Requires approval".to_string()),
                },
            ],
            honeytokens: vec![cop_policy::Honeytoken {
                pattern: "AKIA[0-9A-Z]{16}".to_string(),
                verdict: "deny".to_string(),
                reason: Some("AWS key detected".to_string()),
            }],
        };

        Judge::new(policy).expect("Failed to create judge")
    }

    #[test]
    fn test_pipeline_allow_benign_command() {
        let mut pipeline = LoggingPipeline::new(create_test_judge(), None);
        let input = json!({
            "hook_type": "PreToolUse",
            "timestamp": "2026-10-20T10:00:00Z",
            "tool_name": "bash",
            "tool_input": "echo hello",
            "session_id": "sess-123",
            "user_id": "user-456"
        })
        .to_string();

        let result = pipeline.process(&input);
        assert!(result.is_ok());
        let response = result.unwrap();
        assert_eq!(response.verdict, "allow");
    }

    #[test]
    fn test_pipeline_deny_dangerous_command() {
        let mut pipeline = LoggingPipeline::new(create_test_judge(), None);
        let input = json!({
            "hook_type": "PreToolUse",
            "timestamp": "2026-10-20T10:00:00Z",
            "tool_name": "bash",
            "tool_input": "rm -rf /",
            "session_id": "sess-123",
            "user_id": "user-456"
        })
        .to_string();

        let result = pipeline.process(&input);
        assert!(result.is_ok());
        let response = result.unwrap();
        assert_eq!(response.verdict, "deny");
    }

    #[test]
    fn test_pipeline_honeypot_trap() {
        let mut pipeline = LoggingPipeline::new(create_test_judge(), None);
        let input = json!({
            "hook_type": "PreToolUse",
            "timestamp": "2026-10-20T10:00:00Z",
            "tool_name": "bash",
            "tool_input": "export AWS_KEY=AKIA1234567890ABCDEF",
            "session_id": "sess-123",
            "user_id": "user-456"
        })
        .to_string();

        let result = pipeline.process(&input);
        assert!(result.is_ok());
        let response = result.unwrap();
        assert_eq!(response.verdict, "deny");
        assert!(response.honeypot_alert.is_some());
    }

    #[test]
    fn test_pipeline_invalid_json() {
        let mut pipeline = LoggingPipeline::new(create_test_judge(), None);
        let input = "invalid json";

        let result = pipeline.process(input);
        assert!(result.is_err());
    }

    #[test]
    fn test_pipeline_ask_git_push() {
        let mut pipeline = LoggingPipeline::new(create_test_judge(), None);
        let input = json!({
            "hook_type": "PreToolUse",
            "timestamp": "2026-10-20T10:00:00Z",
            "tool_name": "bash",
            "tool_input": "git push origin main",
            "session_id": "sess-123",
            "user_id": "user-456"
        })
        .to_string();

        let result = pipeline.process(&input);
        assert!(result.is_ok());
        let response = result.unwrap();
        assert_eq!(response.verdict, "ask");
    }

    #[test]
    fn test_pipeline_response_has_fields() {
        let mut pipeline = LoggingPipeline::new(create_test_judge(), None);
        let input = json!({
            "hook_type": "PreToolUse",
            "timestamp": "2026-10-20T10:00:00Z",
            "tool_name": "bash",
            "tool_input": "ls -la",
            "session_id": "sess-123",
            "user_id": "user-456"
        })
        .to_string();

        let result = pipeline.process(&input);
        assert!(result.is_ok());
        let response = result.unwrap();
        assert!(!response.verdict.is_empty());
        assert!(!response.reason.is_empty());
        assert!(response.explanation.is_some());
        assert!(response.rate_limit_status.is_some());
    }
}
