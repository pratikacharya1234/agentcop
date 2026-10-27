//! C2-R judge tests with the real policy/default.toml.
//!
//! Each case is one decision the owner asked to be guarded (2026-10-26 review).
//!
//! PLAN:
//! 1. Load the shipped policy file, so the tests test the real laws.
//! 2. Benign shell that only looks dangerous as text must be allowed.
//! 3. Real actions (writes to installed state, executed secret reads, pushes, evasions) must be denied or asked.
//! 4. Repo sources stay editable. Installed state does not.
//! 5. A command the parser cannot read is denied (fail closed).

use cop_core::{AgentEvent, Verdict};
use cop_policy::{Judge, Policy};
use serde_json::json;

fn judge() -> Judge {
    let policy: Policy =
        toml::from_str(include_str!("../../../policy/default.toml")).expect("policy parses");
    Judge::new(policy).expect("policy compiles")
}

fn bash(cmd: &str) -> AgentEvent {
    AgentEvent {
        hook_event_name: "PreToolUse".to_string(),
        timestamp: "2026-10-26T00:00:00Z".to_string(),
        session_id: Some("judge-test".to_string()),
        user_id: None,
        tool_name: "Bash".to_string(),
        tool_input: json!({ "command": cmd }),
        context: Default::default(),
    }
}

fn edit(path: &str) -> AgentEvent {
    AgentEvent {
        hook_event_name: "PreToolUse".to_string(),
        timestamp: "2026-10-26T00:00:00Z".to_string(),
        session_id: Some("judge-test".to_string()),
        user_id: None,
        tool_name: "Edit".to_string(),
        tool_input: json!({ "file_path": path, "old_string": "a", "new_string": "b" }),
        context: Default::default(),
    }
}

fn verdict(event: &AgentEvent) -> Verdict {
    judge().judge(event).0
}

#[test]
fn stderr_redirect_on_cop_cli_is_allowed() {
    assert_eq!(verdict(&bash("agentcop cases 2>&1")), Verdict::Allow);
}

#[test]
fn grep_for_cop_hook_with_dev_null_is_allowed() {
    assert_eq!(
        verdict(&bash("grep cop-hook src 2>/dev/null")),
        Verdict::Allow
    );
}

#[test]
fn readme_heredoc_mentioning_git_push_is_allowed() {
    let cmd = "cat > README.md <<'EOF'\nAsks before `git push`.\nEOF";
    assert_eq!(verdict(&bash(cmd)), Verdict::Allow);
}

#[test]
fn write_to_installed_policy_is_denied() {
    assert_eq!(
        verdict(&bash("echo x > ~/.agentcop/policy.toml")),
        Verdict::Deny
    );
}

#[test]
fn write_to_installed_policy_via_home_variable_is_denied() {
    assert_eq!(
        verdict(&bash(r#"echo x > "$HOME/.agentcop/policy.toml""#)),
        Verdict::Deny
    );
}

#[test]
fn cd_then_short_name_write_into_installed_state_is_denied() {
    assert_eq!(
        verdict(&bash("cd ~/.agentcop && rm policy.toml")),
        Verdict::Deny
    );
}

#[test]
fn edit_of_installed_settings_is_denied() {
    assert_eq!(
        verdict(&edit("/home/user/.claude/settings.json")),
        Verdict::Deny
    );
}

#[test]
fn edit_of_installed_policy_is_denied() {
    assert_eq!(
        verdict(&edit("/home/user/.agentcop/policy.toml")),
        Verdict::Deny
    );
}

#[test]
fn edit_of_repo_policy_is_allowed() {
    // Repo sources are normal development. Only installed state is protected.
    assert_eq!(
        verdict(&edit("/home/user/project/policy/default.toml")),
        Verdict::Allow
    );
}

#[test]
fn cat_of_env_local_is_denied() {
    assert_eq!(verdict(&bash("cat .env.local")), Verdict::Deny);
}

#[test]
fn git_push_is_asked() {
    assert_eq!(verdict(&bash("git push origin main")), Verdict::Ask);
}

#[test]
fn bash_dash_c_rm_root_is_denied() {
    assert_eq!(verdict(&bash(r#"bash -c "rm -rf /""#)), Verdict::Deny);
}

#[test]
fn split_empty_quotes_rm_root_is_denied() {
    assert_eq!(verdict(&bash("r''m -rf /")), Verdict::Deny);
}

#[test]
fn dev_null_write_is_allowed() {
    assert_eq!(verdict(&bash("echo hi > /dev/null")), Verdict::Allow);
}

#[test]
fn unparseable_command_is_denied() {
    // Fail closed: the judge cannot read it, so it cannot allow it.
    assert_eq!(verdict(&bash("echo \"unterminated")), Verdict::Deny);
}

#[test]
fn daily_log_check_with_stderr_and_installed_path_is_allowed() {
    // The shape that was really denied on 2026-10-26 (row 87): a read of installed state with 2>&1.
    let cmd =
        "./target/debug/agentcop cases 2>&1 | head -60; grep -n mode ~/.agentcop/policy.toml 2>&1";
    assert_eq!(verdict(&bash(cmd)), Verdict::Allow);
}

#[test]
fn bash_input_without_command_text_is_denied() {
    // Fail closed: a Bash event we cannot read a command from must not be allowed by default.
    let mut event = bash("ls");
    event.tool_input = json!("rm -rf /");
    assert_eq!(verdict(&event), Verdict::Deny);
}
