//! C2-R guards: uncertain commands ask, inline code that names protected state is denied,
//! and project instructions and settings are guarded for Bash and the file-edit tools.
//!
//! Uses the shipped policy/default.toml, so the tests check the real laws.
//!
//! PLAN:
//! 1. Uncertain commands (dynamic names, decoded payloads, text piped to a shell) never allow.
//! 2. Inline interpreter code that names .agentcop or .claude/settings is denied; other inline code is allowed.
//! 3. CLAUDE.md changes ask, through Bash and through the file tools.
//! 4. Project settings: any change asks; a change that removes or alters the hook entry is denied.
//! 5. Installed state (~/.agentcop, global settings) stays denied.

use cop_core::{AgentEvent, Verdict};
use cop_policy::{Judge, Policy};
use serde_json::{json, Value};
use std::fs;
use std::path::PathBuf;

fn judge() -> Judge {
    let policy: Policy =
        toml::from_str(include_str!("../../../policy/default.toml")).expect("policy parses");
    Judge::new(policy).expect("policy compiles")
}

fn event(tool: &str, input: Value) -> AgentEvent {
    AgentEvent {
        hook_event_name: "PreToolUse".to_string(),
        timestamp: "2026-10-27T00:00:00Z".to_string(),
        session_id: Some("guards-test".to_string()),
        user_id: None,
        tool_name: tool.to_string(),
        tool_input: input,
        context: Default::default(),
    }
}

fn bash(cmd: &str) -> AgentEvent {
    event("Bash", json!({ "command": cmd }))
}

fn verdict(e: &AgentEvent) -> Verdict {
    judge().judge(e).0
}

fn scratch(name: &str) -> PathBuf {
    let dir = PathBuf::from(env!("CARGO_TARGET_TMPDIR")).join(format!("guards-{name}"));
    let _ = fs::remove_dir_all(&dir);
    fs::create_dir_all(dir.join(".claude")).unwrap();
    dir
}

// 1. Uncertain commands: never allow.

#[test]
fn base64_decode_piped_to_sh_asks() {
    assert_eq!(
        verdict(&bash("echo cm0gLXJmIC8= | base64 -d | sh")),
        Verdict::Ask
    );
}

#[test]
fn command_substitution_name_asks() {
    assert_eq!(verdict(&bash("$(echo rm) -rf /")), Verdict::Ask);
}

#[test]
fn variable_name_asks() {
    assert_eq!(verdict(&bash("X=rm; $X -rf /")), Verdict::Ask);
}

#[test]
fn eval_of_a_variable_asks() {
    assert_eq!(verdict(&bash("eval $x")), Verdict::Ask);
}

#[test]
fn eval_of_literal_destructive_text_denies() {
    assert_eq!(verdict(&bash(r#"eval "rm -rf /""#)), Verdict::Deny);
}

#[test]
fn bash_dash_c_destructive_text_denies() {
    assert_eq!(verdict(&bash(r#"bash -c "rm -rf /""#)), Verdict::Deny);
}

#[test]
fn split_quotes_destructive_text_denies() {
    assert_eq!(verdict(&bash("r''m -rf /")), Verdict::Deny);
}

#[test]
fn text_piped_into_sh_asks() {
    assert_eq!(verdict(&bash("echo hi | sh")), Verdict::Ask);
}

// 2. Inline code that names protected state.

#[test]
fn python_inline_removing_installed_policy_denies() {
    let cmd = r#"python3 -c "import os; os.remove('/home/u/.agentcop/policy.toml')""#;
    assert_eq!(verdict(&bash(cmd)), Verdict::Deny);
}

#[test]
fn sqlite3_on_evidence_db_denies() {
    assert_eq!(
        verdict(&bash(
            r#"sqlite3 ~/.agentcop/evidence.db "delete from cases""#
        )),
        Verdict::Deny
    );
}

#[test]
fn inline_code_that_names_no_protected_path_is_allowed() {
    // Known limit: inline code is judged as text, so this stays allowed (documented in THREAT_MODEL).
    assert_eq!(verdict(&bash(r#"python3 -c "print(1)""#)), Verdict::Allow);
    assert_eq!(
        verdict(&bash(r#"node -e "console.log(1)""#)),
        Verdict::Allow
    );
}

// 3. CLAUDE.md.

#[test]
fn edit_of_claude_md_asks() {
    let e = event(
        "Edit",
        json!({ "file_path": "/home/u/proj/CLAUDE.md", "old_string": "a", "new_string": "b" }),
    );
    assert_eq!(verdict(&e), Verdict::Ask);
}

#[test]
fn write_of_claude_md_asks() {
    let e = event(
        "Write",
        json!({ "file_path": "/home/u/proj/CLAUDE.md", "content": "rules" }),
    );
    assert_eq!(verdict(&e), Verdict::Ask);
}

#[test]
fn bash_append_to_claude_md_asks() {
    assert_eq!(verdict(&bash("echo x >> CLAUDE.md")), Verdict::Ask);
}

// 4. Project settings.

#[test]
fn edit_that_adds_a_key_to_project_settings_asks() {
    let e = event(
        "Edit",
        json!({ "file_path": "/home/u/proj/.claude/settings.json", "old_string": "{", "new_string": "{\"x\":1," }),
    );
    assert_eq!(verdict(&e), Verdict::Ask);
}

#[test]
fn edit_that_removes_the_hook_entry_denies() {
    let e = event(
        "Edit",
        json!({
            "file_path": "/home/u/proj/.claude/settings.local.json",
            "old_string": "\"command\":\"/opt/agentcop/cop-hook\"",
            "new_string": "\"command\":\"true\""
        }),
    );
    assert_eq!(verdict(&e), Verdict::Deny);
}

#[test]
fn multi_edit_that_removes_the_hook_entry_denies() {
    let e = event(
        "MultiEdit",
        json!({
            "file_path": "/home/u/proj/.claude/settings.json",
            "edits": [
                { "old_string": "x", "new_string": "y" },
                { "old_string": "/opt/agentcop/cop-hook", "new_string": "" }
            ]
        }),
    );
    assert_eq!(verdict(&e), Verdict::Deny);
}

#[test]
fn write_that_drops_the_hook_from_an_existing_file_denies() {
    let dir = scratch("drop-hook");
    let file = dir.join(".claude/settings.json");
    fs::write(
        &file,
        r#"{"hooks":{"PreToolUse":[{"hooks":[{"command":"/opt/agentcop/cop-hook"}]}]}}"#,
    )
    .unwrap();
    let e = event(
        "Write",
        json!({ "file_path": file.to_str().unwrap(), "content": "{}" }),
    );
    assert_eq!(verdict(&e), Verdict::Deny);
}

#[test]
fn write_that_keeps_the_hook_asks() {
    let dir = scratch("keep-hook");
    let file = dir.join(".claude/settings.json");
    fs::write(&file, r#"{"command":"/opt/agentcop/cop-hook"}"#).unwrap();
    let e = event(
        "Write",
        json!({ "file_path": file.to_str().unwrap(), "content": "{\"command\":\"/opt/agentcop/cop-hook\",\"a\":1}" }),
    );
    assert_eq!(verdict(&e), Verdict::Ask);
}

#[test]
fn write_of_new_project_settings_asks() {
    let dir = scratch("new-settings");
    let file = dir.join(".claude/settings.local.json");
    let e = event(
        "Write",
        json!({ "file_path": file.to_str().unwrap(), "content": "{}" }),
    );
    assert_eq!(verdict(&e), Verdict::Ask);
}

#[test]
fn bash_sed_that_strips_the_hook_from_settings_denies() {
    let cmd = "sed -i 's/cop-hook//' .claude/settings.local.json";
    assert_eq!(verdict(&bash(cmd)), Verdict::Deny);
}

#[test]
fn bash_overwrite_of_project_settings_asks() {
    assert_eq!(
        verdict(&bash("echo '{}' > .claude/settings.json")),
        Verdict::Ask
    );
}

// 5. Installed state stays denied; repo sources stay allowed.

#[test]
fn edit_of_installed_policy_still_denies() {
    let e = event(
        "Edit",
        json!({ "file_path": "/home/u/.agentcop/policy.toml", "old_string": "a", "new_string": "b" }),
    );
    assert_eq!(verdict(&e), Verdict::Deny);
}

#[test]
fn edit_of_global_settings_still_denies() {
    let e = event(
        "Edit",
        json!({ "file_path": "/home/u/.claude/settings.json", "old_string": "a", "new_string": "b" }),
    );
    assert_eq!(verdict(&e), Verdict::Deny);
}

#[test]
fn edit_of_repo_policy_still_allowed() {
    let e = event(
        "Edit",
        json!({ "file_path": "/home/u/proj/policy/default.toml", "old_string": "a", "new_string": "b" }),
    );
    assert_eq!(verdict(&e), Verdict::Allow);
}
