//! `agentcop fix` tests: run the BUILT binary in a temp HOME, answer its prompt through stdin.
//!
//! Checks:
//! - "no" (or no answer) changes nothing, but the diff is shown
//! - "y" appends one deny rule that matches exactly that command
//! - regex characters and quotes in the command are escaped
//! - unknown case, allow-verdict case, and non-command tools are refused with no change
//! - the suggested rule is always deny

use cop_core::AgentEvent;
use cop_core::Verdict;
use cop_policy::{Judge, Policy};
use std::collections::HashMap;
use std::fs;
use std::io::Write;
use std::path::PathBuf;
use std::process::{Command, Output, Stdio};
use std::sync::atomic::{AtomicUsize, Ordering};

static COUNTER: AtomicUsize = AtomicUsize::new(0);

struct Sandbox {
    root: PathBuf,
}

impl Sandbox {
    fn new() -> Self {
        let n = COUNTER.fetch_add(1, Ordering::SeqCst);
        let root = PathBuf::from(env!("CARGO_TARGET_TMPDIR"))
            .join(format!("fix-{}-{n}", std::process::id()));
        let _ = fs::remove_dir_all(&root);
        fs::create_dir_all(root.join("home/.agentcop")).unwrap();
        let default = fs::read_to_string(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/../../policy/default.toml"
        ))
        .unwrap();
        fs::write(root.join("home/.agentcop/policy.toml"), default).unwrap();
        Sandbox { root }
    }

    fn home(&self) -> PathBuf {
        self.root.join("home")
    }

    fn policy_path(&self) -> PathBuf {
        self.home().join(".agentcop/policy.toml")
    }

    fn policy_text(&self) -> String {
        fs::read_to_string(self.policy_path()).unwrap()
    }

    /// Store one case in the evidence DB and return its CASE-id.
    fn seed(&self, event: &AgentEvent, verdict: Verdict) -> String {
        let db = self.home().join(".agentcop/evidence.db");
        let store = cop_evidence::EvidenceStore::new(&db).unwrap();
        let case = cop_core::Case {
            event: event.clone(),
            verdict,
            evidence_hash: None,
            reason: Some("test".to_string()),
        };
        store.append(&case).unwrap();
        drop(store);
        let conn = rusqlite::Connection::open(&db).unwrap();
        let hash: String = conn
            .query_row("SELECT hash FROM cases ORDER BY id DESC LIMIT 1", [], |r| {
                r.get(0)
            })
            .unwrap();
        format!("CASE-{}", &hash[..12])
    }

    fn run(&self, args: &[&str], answer: &str) -> Output {
        let mut child = Command::new(env!("CARGO_BIN_EXE_agentcop"))
            .args(args)
            .env("HOME", self.home())
            .env_remove("AGENTCOP_POLICY")
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .unwrap();
        child
            .stdin
            .take()
            .unwrap()
            .write_all(answer.as_bytes())
            .unwrap();
        child.wait_with_output().unwrap()
    }

    fn judge_with_current_policy(&self, event: &AgentEvent) -> Verdict {
        let policy: Policy = toml::from_str(&self.policy_text()).unwrap();
        Judge::new(policy).unwrap().judge(event).0
    }
}

fn bash(command: &str) -> AgentEvent {
    AgentEvent {
        hook_event_name: "PreToolUse".to_string(),
        timestamp: "2026-10-23T10:00:00Z".to_string(),
        session_id: Some("sess_fix".to_string()),
        user_id: None,
        tool_name: "Bash".to_string(),
        tool_input: serde_json::json!({ "command": command }),
        context: HashMap::new(),
    }
}

const SAFE_COMMAND: &str = "make deploy-staging";

#[test]
fn no_answer_changes_nothing_and_shows_the_diff() {
    let sb = Sandbox::new();
    let id = sb.seed(&bash(SAFE_COMMAND), Verdict::Deny);
    let before = sb.policy_text();
    let out = sb.run(&["fix", &id], "n\n");
    assert!(
        out.status.success(),
        "stderr: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(
        stdout.contains("Apply?"),
        "must ask before applying: {stdout}"
    );
    // regex::escape turns "-" into "\-", so check the part of the command that has no special characters.
    assert!(
        stdout
            .lines()
            .any(|l| l.starts_with('+') && l.contains(r#""command":"make deploy"#)),
        "diff: {stdout}"
    );
    assert_eq!(
        sb.policy_text(),
        before,
        "policy must not change without yes"
    );
}

#[test]
fn empty_answer_is_no() {
    let sb = Sandbox::new();
    let id = sb.seed(&bash(SAFE_COMMAND), Verdict::Deny);
    let before = sb.policy_text();
    let out = sb.run(&["fix", &id], "");
    assert!(out.status.success());
    assert_eq!(sb.policy_text(), before);
}

#[test]
fn yes_appends_one_deny_rule_matching_exactly_that_command() {
    let sb = Sandbox::new();
    let id = sb.seed(&bash(SAFE_COMMAND), Verdict::Deny);
    assert_eq!(
        sb.judge_with_current_policy(&bash(SAFE_COMMAND)),
        Verdict::Allow,
        "precondition"
    );
    let before_rules = sb.policy_text().matches("[[rules]]").count();

    let out = sb.run(&["fix", &id], "y\n");
    assert!(
        out.status.success(),
        "stderr: {}",
        String::from_utf8_lossy(&out.stderr)
    );

    let after = sb.policy_text();
    assert_eq!(
        after.matches("[[rules]]").count(),
        before_rules + 1,
        "exactly one rule added"
    );
    assert_eq!(
        sb.judge_with_current_policy(&bash(SAFE_COMMAND)),
        Verdict::Deny
    );
    assert_eq!(
        sb.judge_with_current_policy(&bash("make deploy-staging-2")),
        Verdict::Allow,
        "exact match: a longer command is not blocked"
    );
    assert!(
        sb.home().join(".agentcop/policy.toml.bak").exists(),
        "backup written"
    );
}

#[test]
fn regex_characters_and_quotes_are_escaped() {
    let sb = Sandbox::new();
    // Valid bash with regex special characters. `(x)` bare is a syntax error, so it is quoted.
    let cmd = r#"echo "a.b*c" "(x)""#;
    let id = sb.seed(&bash(cmd), Verdict::Deny);
    let out = sb.run(&["fix", &id], "y\n");
    assert!(
        out.status.success(),
        "stderr: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    assert_eq!(sb.judge_with_current_policy(&bash(cmd)), Verdict::Deny);
    assert_eq!(
        sb.judge_with_current_policy(&bash(r#"echo "aXb*c" "(x)""#)),
        Verdict::Allow,
        "the dot and star must not act as wildcards"
    );
}

#[test]
fn every_suggested_rule_is_deny() {
    let sb = Sandbox::new();
    let id = sb.seed(&bash(SAFE_COMMAND), Verdict::Deny);
    let before = sb.policy_text();
    sb.run(&["fix", &id], "y\n");
    let added = &sb.policy_text()[before.len()..];
    assert!(added.contains("verdict = \"deny\""), "added rule: {added}");
    assert!(
        !added.contains("verdict = \"allow\""),
        "added rule: {added}"
    );
}

#[test]
fn unknown_case_is_refused_with_no_change() {
    let sb = Sandbox::new();
    sb.seed(&bash(SAFE_COMMAND), Verdict::Deny);
    let before = sb.policy_text();
    let out = sb.run(&["fix", "CASE-ffffffffffff"], "y\n");
    assert!(!out.status.success());
    assert_eq!(sb.policy_text(), before);
}

#[test]
fn allow_verdict_case_is_refused_with_no_change() {
    let sb = Sandbox::new();
    let id = sb.seed(&bash(SAFE_COMMAND), Verdict::Allow);
    let before = sb.policy_text();
    let out = sb.run(&["fix", &id], "y\n");
    assert!(!out.status.success());
    assert_eq!(sb.policy_text(), before);
}

#[test]
fn non_command_tool_is_refused_with_no_change() {
    let sb = Sandbox::new();
    let mut event = bash(SAFE_COMMAND);
    event.tool_name = "Read".to_string();
    event.tool_input = serde_json::json!({ "file_path": "/etc/hosts" });
    let id = sb.seed(&event, Verdict::Deny);
    let before = sb.policy_text();
    let out = sb.run(&["fix", &id], "y\n");
    assert!(!out.status.success());
    assert_eq!(sb.policy_text(), before);
}

#[test]
fn cases_lists_ids_that_fix_accepts() {
    let sb = Sandbox::new();
    sb.seed(&bash(SAFE_COMMAND), Verdict::Deny);
    let listing = Command::new(env!("CARGO_BIN_EXE_agentcop"))
        .arg("cases")
        .env("HOME", sb.home())
        .output()
        .unwrap();
    assert!(listing.status.success());
    let stdout = String::from_utf8_lossy(&listing.stdout).into_owned();
    assert!(
        stdout.contains("test"),
        "cases must show each case's reason: {stdout}"
    );
    let id = stdout
        .split_whitespace()
        .find(|w| w.starts_with("CASE-"))
        .unwrap_or_else(|| panic!("cases must print a CASE- id: {stdout}"));
    let out = sb.run(&["fix", id], "n\n");
    assert!(
        out.status.success(),
        "fix must accept the id from cases: {id}"
    );
}
