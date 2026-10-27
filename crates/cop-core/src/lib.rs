//! Shared types for AgentCop: AgentEvent, Verdict, Case
//!
//! PLAN:
//! 1. Define AgentEvent struct: tool_name, tool_input, context metadata
//! 2. Define Verdict enum: Allow, Ask, Deny
//! 3. Define Case struct: event + verdict + evidence hash
//! 4. Add serde for JSON parsing/serialization
//! 5. Parse real Claude Code PreToolUse JSON fixtures

pub enum Verdict {
    Allow,
    Ask,
    Deny,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn verdict_enum_exists() {
        let _ = Verdict::Allow;
    }
}
