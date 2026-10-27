//! Judge: rules, normalizer, strictness, honeytokens
//!
//! PLAN:
//! 1. Load TOML rules file
//! 2. Compile regex patterns once
//! 3. Implement strictest-wins logic: Deny > Ask > Allow
//! 4. Add honeytoken matching
//! 5. Judge an AgentEvent and return a Verdict

#[cfg(test)]
mod tests {
    #[test]
    fn skeleton_compiles() {
        // Phase A2 will add policy judge tests
    }
}
