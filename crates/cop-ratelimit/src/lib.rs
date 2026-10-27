//! Speed limits: rate limiting at policy level
//!
//! PLAN:
//! 1. RateLimitPolicy: calls_per_minute, bytes_per_minute
//! 2. SessionLimiter: track usage per session_id
//! 3. UserLimiter: track usage per user_id
//! 4. LimitChecker: validate against policies
//! 5. Tests: respect limits, track per session/user, reset over time

use cop_core::AgentEvent;
use std::collections::HashMap;
use std::time::{Duration, Instant};

/// Rate limit policy
#[derive(Debug, Clone)]
pub struct RateLimitPolicy {
    pub calls_per_minute: u32,
    pub bytes_per_minute: u64,
}

impl RateLimitPolicy {
    /// Create a new rate limit policy
    pub fn new(calls: u32, bytes: u64) -> Self {
        RateLimitPolicy {
            calls_per_minute: calls,
            bytes_per_minute: bytes,
        }
    }

    /// Standard policy: 60 calls/min, 1MB/min
    pub fn standard() -> Self {
        RateLimitPolicy {
            calls_per_minute: 60,
            bytes_per_minute: 1024 * 1024,
        }
    }

    /// Strict policy: 10 calls/min, 100KB/min
    pub fn strict() -> Self {
        RateLimitPolicy {
            calls_per_minute: 10,
            bytes_per_minute: 100 * 1024,
        }
    }
}

/// Usage tracking entry
#[derive(Debug, Clone)]
struct UsageWindow {
    calls: u32,
    bytes: u64,
    window_start: Instant,
}

/// Rate limiter for a single session
pub struct SessionLimiter {
    usage: UsageWindow,
    policy: RateLimitPolicy,
}

impl SessionLimiter {
    /// Create a new session limiter
    pub fn new(policy: RateLimitPolicy) -> Self {
        SessionLimiter {
            usage: UsageWindow {
                calls: 0,
                bytes: 0,
                window_start: Instant::now(),
            },
            policy,
        }
    }

    /// Check if an event is allowed (doesn't exceed limits)
    pub fn check(&mut self, event: &AgentEvent) -> bool {
        // Reset window if a minute has passed
        if self.usage.window_start.elapsed() > Duration::from_secs(60) {
            self.usage.calls = 0;
            self.usage.bytes = 0;
            self.usage.window_start = Instant::now();
        }

        // Check if adding this event would exceed limits
        let event_bytes = event.tool_name.len() + event.tool_input.to_string().len();

        if self.usage.calls >= self.policy.calls_per_minute {
            return false; // Calls exceeded
        }

        if self.usage.bytes.saturating_add(event_bytes as u64) > self.policy.bytes_per_minute {
            return false; // Bytes exceeded
        }

        // Usage is OK, record it
        self.usage.calls += 1;
        self.usage.bytes += event_bytes as u64;

        true
    }

    /// Get current usage
    pub fn usage(&self) -> (u32, u64) {
        (self.usage.calls, self.usage.bytes)
    }
}

/// Rate limiter per user
pub struct UserLimiter {
    sessions: HashMap<String, SessionLimiter>,
    policy: RateLimitPolicy,
}

impl UserLimiter {
    /// Create a new user limiter
    pub fn new(policy: RateLimitPolicy) -> Self {
        UserLimiter {
            sessions: HashMap::new(),
            policy,
        }
    }

    /// Check if an event from a session is allowed
    pub fn check(&mut self, session_id: &str, event: &AgentEvent) -> bool {
        self.sessions
            .entry(session_id.to_string())
            .or_insert_with(|| SessionLimiter::new(self.policy.clone()))
            .check(event)
    }

    /// Get usage for a session
    pub fn session_usage(&self, session_id: &str) -> Option<(u32, u64)> {
        self.sessions.get(session_id).map(|s| s.usage())
    }
}

/// Global rate limit checker
pub struct LimitChecker {
    users: HashMap<String, UserLimiter>,
    policy: RateLimitPolicy,
}

impl LimitChecker {
    /// Create a new limit checker
    pub fn new(policy: RateLimitPolicy) -> Self {
        LimitChecker {
            users: HashMap::new(),
            policy,
        }
    }

    /// Check if an event is allowed
    pub fn check(&mut self, user_id: &str, session_id: &str, event: &AgentEvent) -> bool {
        self.users
            .entry(user_id.to_string())
            .or_insert_with(|| UserLimiter::new(self.policy.clone()))
            .check(session_id, event)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashMap;

    fn sample_event(tool: &str) -> AgentEvent {
        AgentEvent {
            hook_type: "PreToolUse".to_string(),
            timestamp: "2026-10-20T10:00:00Z".to_string(),
            session_id: Some("s123".to_string()),
            user_id: Some("u456".to_string()),
            tool_name: tool.to_string(),
            tool_input: serde_json::json!({"data": "x".repeat(100)}),
            context: HashMap::new(),
        }
    }

    #[test]
    fn policy_standard() {
        let policy = RateLimitPolicy::standard();
        assert_eq!(policy.calls_per_minute, 60);
        assert!(policy.bytes_per_minute >= 1024 * 1024);
    }

    #[test]
    fn policy_strict() {
        let policy = RateLimitPolicy::strict();
        assert_eq!(policy.calls_per_minute, 10);
        assert!(policy.bytes_per_minute >= 100 * 1024);
    }

    #[test]
    fn session_limiter_allows_within_limit() {
        let policy = RateLimitPolicy::new(10, 10000);
        let mut limiter = SessionLimiter::new(policy);

        let event = sample_event("bash");
        assert!(limiter.check(&event)); // First call should be allowed
        assert!(limiter.check(&event)); // Second call should be allowed
    }

    #[test]
    fn session_limiter_exceeds_calls() {
        let policy = RateLimitPolicy::new(2, 100000);
        let mut limiter = SessionLimiter::new(policy);

        let event = sample_event("bash");
        assert!(limiter.check(&event)); // 1st
        assert!(limiter.check(&event)); // 2nd
        assert!(!limiter.check(&event)); // 3rd - exceeds limit
    }

    #[test]
    fn session_limiter_exceeds_bytes() {
        let policy = RateLimitPolicy::new(100, 500); // 500 bytes limit
        let mut limiter = SessionLimiter::new(policy);

        let event = sample_event("bash"); // ~130 bytes (tool name + input)
        assert!(limiter.check(&event)); // 1st - OK
        assert!(limiter.check(&event)); // 2nd - OK
        assert!(limiter.check(&event)); // 3rd - exceeds 500 bytes
    }

    #[test]
    fn user_limiter_separate_sessions() {
        let policy = RateLimitPolicy::new(1, 10000);
        let mut limiter = UserLimiter::new(policy);

        let event = sample_event("bash");

        // Session 1
        assert!(limiter.check("s1", &event)); // Allowed in s1
        assert!(!limiter.check("s1", &event)); // Denied in s1 (limit exceeded)

        // Session 2 - should have separate limit
        assert!(limiter.check("s2", &event)); // Allowed in s2
        assert!(!limiter.check("s2", &event)); // Denied in s2
    }

    #[test]
    fn user_limiter_usage_tracking() {
        let policy = RateLimitPolicy::new(10, 10000);
        let mut limiter = UserLimiter::new(policy);

        let event = sample_event("bash");
        limiter.check("s1", &event);

        let usage = limiter.session_usage("s1");
        assert!(usage.is_some());
        let (calls, _bytes) = usage.unwrap();
        assert_eq!(calls, 1);
    }

    #[test]
    fn limit_checker_separates_users() {
        let policy = RateLimitPolicy::new(1, 10000);
        let mut checker = LimitChecker::new(policy);

        let event = sample_event("bash");

        // User 1
        assert!(checker.check("u1", "s1", &event)); // Allowed
        assert!(!checker.check("u1", "s1", &event)); // Denied

        // User 2 - should have separate limit
        assert!(checker.check("u2", "s1", &event)); // Allowed
    }

    #[test]
    fn rate_limit_policy_creation() {
        let policy = RateLimitPolicy::new(50, 500000);
        assert_eq!(policy.calls_per_minute, 50);
        assert_eq!(policy.bytes_per_minute, 500000);
    }
}
