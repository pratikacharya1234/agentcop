//! C2-R end to end: the guard list, run through the real cop-hook binary.
//!
//! Each call is a separate process with its own session and a temp HOME,
//! so the Rule of Two state of one case cannot leak into another.
//!
//! PLAN:
//! 1. Build the hook event JSON for one Bash command.
//! 2. Run cop-hook with the shipped policy and taint rules.
//! 3. Read permissionDecision from stdout. Anything unreadable fails the test.
//! 4. One test per guard line from the owner's C2-R approval.

use std::fs;
use std::io::Write;
use std::path::PathBuf;
use std::process::{Command, Stdio};
use std::sync::atomic::{AtomicUsize, Ordering};

static COUNTER: AtomicUsize = AtomicUsize::new(0);

fn fresh_home() -> PathBuf {
    let n = COUNTER.fetch_add(1, Ordering::SeqCst);
    let home =
        PathBuf::from(env!("CARGO_TARGET_TMPDIR")).join(format!("c2r-{}-{n}", std::process::id()));
    let _ = fs::remove_dir_all(&home);
    fs::create_dir_all(home.join(".agentcop")).unwrap();
    home
}

/// Run the hook for one Bash command. Returns the permissionDecision.
fn decide(command: &str) -> String {
    decide_tool("Bash", serde_json::json!({ "command": command }))
}

/// Run the hook for one tool call with the given input. Returns the permissionDecision.
fn decide_tool(tool: &str, input: serde_json::Value) -> String {
    let home = fresh_home();
    let event = serde_json::json!({
        "hook_event_name": "PreToolUse",
        "session_id": format!("c2r-{}", COUNTER.load(Ordering::SeqCst)),
        "timestamp": "2026-10-26T10:00:00Z",
        "tool_name": tool,
        "tool_input": input,
    });
    let mut child = Command::new(env!("CARGO_BIN_EXE_cop-hook"))
        .env_clear()
        .env("HOME", &home)
        .env(
            "AGENTCOP_POLICY",
            concat!(env!("CARGO_MANIFEST_DIR"), "/../../policy/default.toml"),
        )
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    child
        .stdin
        .take()
        .unwrap()
        .write_all(event.to_string().as_bytes())
        .unwrap();
    let out = child.wait_with_output().unwrap();
    let json: serde_json::Value = serde_json::from_slice(&out.stdout)
        .unwrap_or_else(|e| panic!("no JSON verdict for {event}: {e}"));
    json["hookSpecificOutput"]["permissionDecision"]
        .as_str()
        .unwrap_or_else(|| panic!("no decision for {event}"))
        .to_string()
}

#[test]
fn stderr_redirect_on_agentcop_cases_is_allowed() {
    assert_eq!(decide("agentcop cases 2>&1"), "allow");
}

#[test]
fn grep_cop_hook_with_dev_null_is_allowed() {
    assert_eq!(decide("grep cop-hook src 2>/dev/null"), "allow");
}

#[test]
fn readme_heredoc_containing_git_push_is_allowed() {
    let cmd = "cat > README.md <<'EOF'\nAsks before `git push`.\nEOF";
    assert_eq!(decide(cmd), "allow");
}

#[test]
fn echo_into_installed_policy_is_denied() {
    assert_eq!(decide("echo x > ~/.agentcop/policy.toml"), "deny");
}

#[test]
fn cat_env_local_is_denied() {
    assert_eq!(decide("cat .env.local"), "deny");
}

#[test]
fn git_push_origin_main_is_asked() {
    assert_eq!(decide("git push origin main"), "ask");
}

#[test]
fn bash_dash_c_rm_root_is_denied() {
    assert_eq!(decide(r#"bash -c "rm -rf /""#), "deny");
}

#[test]
fn split_quotes_rm_root_is_denied() {
    assert_eq!(decide("r''m -rf /"), "deny");
}

#[test]
fn unparseable_command_is_denied() {
    assert_eq!(decide("echo \"unterminated"), "deny");
}

#[test]
fn daily_log_check_with_stderr_and_installed_path_is_allowed() {
    let cmd =
        "./target/debug/agentcop cases 2>&1 | head -60; grep -n mode ~/.agentcop/policy.toml 2>&1";
    assert_eq!(decide(cmd), "allow");
}

// C2-R part 2: uncertain commands ask, inline protected state is denied, project files are guarded.

#[test]
fn base64_decode_piped_to_sh_asks() {
    assert_eq!(decide("echo cm0gLXJmIC8= | base64 -d | sh"), "ask");
}

#[test]
fn command_substitution_name_asks() {
    assert_eq!(decide("$(echo rm) -rf /"), "ask");
}

#[test]
fn variable_name_asks() {
    assert_eq!(decide("X=rm; $X -rf /"), "ask");
}

#[test]
fn eval_of_literal_destructive_text_is_denied() {
    assert_eq!(decide(r#"eval "rm -rf /""#), "deny");
}

#[test]
fn inline_python_removing_installed_policy_is_denied() {
    let cmd = r#"python3 -c "import os; os.remove('/home/u/.agentcop/policy.toml')""#;
    assert_eq!(decide(cmd), "deny");
}

#[test]
fn edit_tool_on_claude_md_asks() {
    let input = serde_json::json!({
        "file_path": "/home/u/proj/CLAUDE.md",
        "old_string": "a",
        "new_string": "b"
    });
    assert_eq!(decide_tool("Edit", input), "ask");
}

#[test]
fn edit_tool_removing_the_project_hook_is_denied() {
    let input = serde_json::json!({
        "file_path": "/home/u/proj/.claude/settings.json",
        "old_string": "/opt/agentcop/cop-hook",
        "new_string": "/bin/true"
    });
    assert_eq!(decide_tool("Edit", input), "deny");
}
