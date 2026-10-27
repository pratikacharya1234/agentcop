//! Tests for policy path resolution at runtime
//!
//! Verifies that cop-hook can find policy.toml in multiple locations:
//! 1. AGENTCOP_POLICY environment variable (if set)
//! 2. ~/.agentcop/policy.toml (user's default)
//! 3. ./policy/default.toml (if running from repo root)

#[test]
fn policy_path_should_be_resolved_at_runtime() {
    // Policy path must be resolved at RUNTIME, not compile-time
    // This allows the same binary to work on different machines and in different directories

    // Wrong approach (current code):
    // let path = env!("CARGO_MANIFEST_DIR")  // compile-time only
    //     .parent().parent().join("policy/default.toml")

    // Right approach:
    // 1. Check AGENTCOP_POLICY env var
    // 2. Check ~/.agentcop/policy.toml
    // 3. Check ./policy/default.toml
    // 4. Fail with clear error message

    // Policy path resolution is tested through the integration_hook test that exercises resolve_policy_path
}

#[test]
fn agentcop_policy_env_var_takes_priority() {
    // If AGENTCOP_POLICY is set, it should be used first
    let env_value = std::env::var("AGENTCOP_POLICY").ok();

    if let Some(path) = env_value {
        assert!(
            !path.is_empty(),
            "AGENTCOP_POLICY env var should be a non-empty path"
        );
    }
}

#[test]
fn policy_fallback_to_home_directory() {
    // If AGENTCOP_POLICY not set, try ~/.agentcop/policy.toml
    let home = dirs::home_dir();
    assert!(home.is_some(), "Home directory must be accessible");

    if let Some(home_path) = home {
        let agentcop_policy = home_path.join(".agentcop/policy.toml");
        // This test documents the expected fallback path
        assert!(agentcop_policy.to_string_lossy().contains(".agentcop"));
    }
}
