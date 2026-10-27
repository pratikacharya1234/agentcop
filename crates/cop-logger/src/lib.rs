//! Verdict logging and aggregation
//!
//! PLAN:
//! 1. VerdictLog: format Case → human-readable log entry
//! 2. RateLimiter: tokens-per-second throttle
//! 3. Logger: combines formatter + limiter + output
//! 4. Tests: format verdicts, rate limit, multiple outputs

use chrono::Utc;
use cop_core::{Case, Verdict};
use std::sync::atomic::{AtomicU32, Ordering};
use std::sync::Arc;
use std::time::Instant;

/// Format a verdict case as a log entry
pub struct VerdictLog;

impl VerdictLog {
    /// Format Case into a human-readable log line
    pub fn format(case: &Case) -> String {
        let verdict_str = match case.verdict {
            Verdict::Allow => "ALLOW",
            Verdict::Ask => "ASK",
            Verdict::Deny => "DENY",
        };

        let timestamp = Utc::now().to_rfc3339_opts(chrono::SecondsFormat::Secs, true);
        let reason = case.reason.as_deref().unwrap_or("(no reason)");
        let tool = &case.event.tool_name;

        format!(
            "[{}] {} {} | tool={} | {}",
            timestamp, verdict_str, "VERDICT", tool, reason
        )
    }
}

/// Rate limiter using token bucket algorithm
pub struct RateLimiter {
    tokens: Arc<AtomicU32>,
    refill_time: Arc<parking_lot::Mutex<Instant>>,
    tokens_per_second: u32,
}

impl RateLimiter {
    /// Create a rate limiter with tokens_per_second limit
    pub fn new(tokens_per_second: u32) -> Self {
        RateLimiter {
            tokens: Arc::new(AtomicU32::new(tokens_per_second)),
            refill_time: Arc::new(parking_lot::Mutex::new(Instant::now())),
            tokens_per_second,
        }
    }

    /// Check if an event can be logged (consumes a token if yes)
    pub fn allow(&self) -> bool {
        let mut refill = self.refill_time.lock();
        let elapsed = refill.elapsed();
        let seconds = elapsed.as_secs_f32();

        // Refill tokens based on elapsed time
        let tokens_to_add = (seconds * self.tokens_per_second as f32) as u32;
        if tokens_to_add > 0 {
            let current = self.tokens.load(Ordering::Relaxed);
            let new_tokens = (current + tokens_to_add).min(self.tokens_per_second);
            self.tokens.store(new_tokens, Ordering::Relaxed);
            *refill = Instant::now();
        }

        // Try to consume a token
        let current = self.tokens.load(Ordering::Relaxed);
        if current > 0 {
            self.tokens.store(current - 1, Ordering::Relaxed);
            true
        } else {
            false
        }
    }

    /// Get current token count
    pub fn tokens(&self) -> u32 {
        self.tokens.load(Ordering::Relaxed)
    }
}

/// Verdict logger with rate limiting
pub struct Logger {
    limiter: RateLimiter,
}

impl Logger {
    /// Create a new logger with tokens_per_second limit
    pub fn new(tokens_per_second: u32) -> Self {
        Logger {
            limiter: RateLimiter::new(tokens_per_second),
        }
    }

    /// Log a verdict case if rate limit allows
    pub fn log(&self, case: &Case) -> Option<String> {
        if self.limiter.allow() {
            Some(VerdictLog::format(case))
        } else {
            None
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use cop_core::{AgentEvent, Verdict};
    use std::collections::HashMap;
    use std::thread;
    use std::time::Duration;

    fn sample_case() -> Case {
        Case {
            event: AgentEvent {
                hook_type: "PreToolUse".to_string(),
                timestamp: Utc::now().to_rfc3339_opts(chrono::SecondsFormat::Secs, true),
                session_id: Some("s123".to_string()),
                user_id: Some("u123".to_string()),
                tool_name: "bash".to_string(),
                tool_input: serde_json::json!({"command": "echo hello"}),
                context: HashMap::new(),
            },
            verdict: Verdict::Allow,
            evidence_hash: None,
            reason: Some("Safe command".to_string()),
        }
    }

    #[test]
    fn format_allow_verdict() {
        let case = sample_case();
        let log = VerdictLog::format(&case);
        assert!(log.contains("ALLOW"));
        assert!(log.contains("bash"));
        assert!(log.contains("Safe command"));
    }

    #[test]
    fn format_deny_verdict() {
        let mut case = sample_case();
        case.verdict = Verdict::Deny;
        case.reason = Some("Dangerous rm command".to_string());
        let log = VerdictLog::format(&case);
        assert!(log.contains("DENY"));
        assert!(log.contains("Dangerous rm command"));
    }

    #[test]
    fn format_ask_verdict() {
        let mut case = sample_case();
        case.verdict = Verdict::Ask;
        case.reason = Some("Needs approval: git push".to_string());
        let log = VerdictLog::format(&case);
        assert!(log.contains("ASK"));
        assert!(log.contains("git push"));
    }

    #[test]
    fn format_missing_reason() {
        let mut case = sample_case();
        case.reason = None;
        let log = VerdictLog::format(&case);
        assert!(log.contains("no reason"));
    }

    #[test]
    fn rate_limiter_allows_up_to_limit() {
        let limiter = RateLimiter::new(3);
        assert!(limiter.allow()); // 1st
        assert!(limiter.allow()); // 2nd
        assert!(limiter.allow()); // 3rd
        assert!(!limiter.allow()); // 4th rejected
    }

    #[test]
    fn rate_limiter_refills_over_time() {
        let limiter = RateLimiter::new(2);
        assert!(limiter.allow()); // consume 1
        assert!(limiter.allow()); // consume 1
        assert!(!limiter.allow()); // empty

        // Wait for refill (need at least 1 second for 1 token with 2 TPS = 0.5s per token)
        thread::sleep(Duration::from_millis(600));
        assert!(limiter.allow()); // should refill and allow 1
    }

    #[test]
    fn logger_formats_and_limits() {
        let logger = Logger::new(2);
        let case = sample_case();

        let log1 = logger.log(&case);
        assert!(log1.is_some());
        assert!(log1.unwrap().contains("ALLOW"));

        let log2 = logger.log(&case);
        assert!(log2.is_some());

        let log3 = logger.log(&case);
        assert!(log3.is_none()); // Rate limited
    }

    #[test]
    fn logger_refills_tokens() {
        let logger = Logger::new(1);
        assert!(logger.log(&sample_case()).is_some());
        assert!(logger.log(&sample_case()).is_none());

        thread::sleep(Duration::from_millis(1100));
        assert!(logger.log(&sample_case()).is_some()); // Refilled
    }
}
