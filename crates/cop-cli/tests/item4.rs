//! Item 4 (2026-10-27): the canary gate in install, doctor's mode check, purge of interim archives, and a clean
//! uninstall. Each case runs the built agentcop in its own temp HOME.
use std::fs;
use std::io::Write;
use std::path::{Path, PathBuf};
use std::process::{Command, Output, Stdio};

const DEFAULT: &str = include_str!("../../../policy/default.toml");

fn sandbox(name: &str) -> PathBuf {
    let dir = PathBuf::from(env!("CARGO_TARGET_TMPDIR"))
        .join(format!("item4-{name}-{}", std::process::id()));
    let _ = fs::remove_dir_all(&dir);
    fs::create_dir_all(dir.join("home/.claude")).unwrap();
    fs::create_dir_all(dir.join("work")).unwrap();
    fs::write(
        dir.join("home/.claude/settings.json"),
        r#"{"model":"sonnet","hooks":{"PreToolUse":[{"matcher":"Write","hooks":[{"type":"command","command":"echo keep-me"}]}]}}"#,
    )
    .unwrap();
    // A stand-in hook, executable, that answers --version like the real one.
    let hook = dir.join("stand-in-cop-hook");
    fs::write(
        &hook,
        "#!/bin/sh\nif [ \"$1\" = \"--version\" ]; then echo \"cop-hook 0.0.1\"; fi\nexit 0\n",
    )
    .unwrap();
    fs::set_permissions(&hook, std::os::unix::fs::PermissionsExt::from_mode(0o755)).unwrap();
    dir
}

fn run(dir: &Path, args: &[&str], stdin: &str, extra_env: &[(&str, String)]) -> Output {
    let mut cmd = Command::new(env!("CARGO_BIN_EXE_agentcop"));
    cmd.args(args)
        .env_clear()
        .env("HOME", dir.join("home"))
        .env("AGENTCOP_HOOK", dir.join("stand-in-cop-hook"))
        .current_dir(dir.join("work"))
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    for (k, v) in extra_env {
        cmd.env(k, v);
    }
    let mut child = cmd.spawn().unwrap();
    child
        .stdin
        .take()
        .unwrap()
        .write_all(stdin.as_bytes())
        .unwrap();
    child.wait_with_output().unwrap()
}

// 1. Canary gate.

#[test]
fn install_refuses_a_policy_that_allows_a_canary_and_names_it() {
    let dir = sandbox("gate");
    // Today's broken rm quoting: the rm rule's pattern begins with two extra quotes, so it matches nothing.
    let broken = DEFAULT.replacen("pattern = '''rm", "pattern = '''''rm", 1);
    let policy = dir.join("broken-default.toml");
    fs::write(&policy, broken).unwrap();
    let before = fs::read(dir.join("home/.claude/settings.json")).unwrap();
    let out = run(
        &dir,
        &["install"],
        "",
        &[(
            "AGENTCOP_DEFAULT_POLICY",
            policy.to_string_lossy().into_owned(),
        )],
    );
    let err = String::from_utf8_lossy(&out.stderr).to_string();
    assert!(!out.status.success(), "install must refuse: {err}");
    assert!(
        err.contains("rm -rf /"),
        "the refusal must name the canary: {err}"
    );
    assert_eq!(
        fs::read(dir.join("home/.claude/settings.json")).unwrap(),
        before,
        "settings untouched"
    );
    assert!(
        !dir.join("home/.agentcop/policy.toml").exists(),
        "no policy written"
    );
}

#[test]
fn install_accepts_the_shipped_policy() {
    let dir = sandbox("accept");
    let out = run(&dir, &["install"], "", &[]);
    assert!(
        out.status.success(),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
    let s: serde_json::Value =
        serde_json::from_str(&fs::read_to_string(dir.join("home/.claude/settings.json")).unwrap())
            .unwrap();
    assert!(!contains_null(&s), "no null keys: {s}");
}

fn contains_null(v: &serde_json::Value) -> bool {
    match v {
        serde_json::Value::Null => true,
        serde_json::Value::Array(a) => a.iter().any(contains_null),
        serde_json::Value::Object(o) => o.values().any(contains_null),
        _ => false,
    }
}

// 2. SessionStart is registered, and uninstall is clean.

#[test]
fn install_registers_a_session_start_heartbeat_and_pre_tool_use_still_blocks() {
    let dir = sandbox("events");
    assert!(run(&dir, &["install"], "", &[]).status.success());
    let s: serde_json::Value =
        serde_json::from_str(&fs::read_to_string(dir.join("home/.claude/settings.json")).unwrap())
            .unwrap();
    assert!(!contains_null(&s), "install must not insert null keys: {s}");
    let start = &s["hooks"]["SessionStart"][0]["hooks"][0];
    assert!(start["command"]
        .as_str()
        .unwrap()
        .ends_with(".agentcop/bin/cop-hook"));
    assert!(
        start.get("onFailure").is_none(),
        "a heartbeat never blocks a session"
    );
    let pre = &s["hooks"]["PreToolUse"].as_array().unwrap().last().unwrap()["hooks"][0];
    assert_eq!(pre["onFailure"], "block", "PreToolUse still fails closed");
}

#[test]
fn uninstall_restores_the_original_bytes_and_keeps_evidence() {
    let dir = sandbox("uninstall");
    let original = fs::read(dir.join("home/.claude/settings.json")).unwrap();
    assert!(run(&dir, &["install"], "", &[]).status.success());
    fs::write(dir.join("home/.agentcop/evidence.db"), b"evidence stays").unwrap();
    let out = run(&dir, &["uninstall"], "", &[]);
    assert!(
        out.status.success(),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
    assert_eq!(
        fs::read(dir.join("home/.claude/settings.json")).unwrap(),
        original,
        "byte-identical to the backup"
    );
    assert!(
        dir.join("home/.agentcop/evidence.db").exists(),
        "evidence stays without --purge"
    );
    assert!(
        !dir.join("home/.agentcop/bin/cop-hook").exists(),
        "the hook copy is removed"
    );
}

#[test]
fn uninstall_purge_asks_and_a_no_keeps_everything() {
    let dir = sandbox("purge");
    assert!(run(&dir, &["install"], "", &[]).status.success());
    let out = run(&dir, &["uninstall", "--purge"], "n\n", &[]);
    assert!(String::from_utf8_lossy(&out.stdout).contains("Nothing deleted"));
    assert!(dir.join("home/.agentcop/policy.toml").exists());
}

// 3. Doctor: a mode problem is a FAIL with its fix.

#[test]
fn doctor_fails_a_loose_file_and_names_the_fix() {
    let dir = sandbox("doctor");
    assert!(run(&dir, &["install"], "", &[]).status.success());
    let policy = dir.join("home/.agentcop/policy.toml");
    fs::set_permissions(&policy, std::os::unix::fs::PermissionsExt::from_mode(0o664)).unwrap();
    let out = run(&dir, &["doctor"], "", &[]);
    let text = String::from_utf8_lossy(&out.stdout).to_string();
    assert!(text.contains("FAIL  modes"), "{text}");
    assert!(text.contains("chmod 600"), "the fix is printed: {text}");
    assert_eq!(out.status.code(), Some(1), "doctor exits 1 on a failure");
}

// 4. Purge covers interim archives too, and asks first.

#[test]
fn purge_legacy_lists_interim_archives_with_sizes_and_asks() {
    let dir = sandbox("interim");
    assert!(run(&dir, &["install"], "", &[]).status.success());
    let interim = dir.join("home/.agentcop/evidence-interim-20261026-000000.db");
    fs::write(&interim, vec![0u8; 4096]).unwrap();
    let out = run(&dir, &["evidence", "purge-legacy"], "n\n", &[]);
    let text = String::from_utf8_lossy(&out.stdout).to_string();
    assert!(
        text.contains("evidence-interim-20261026-000000.db (4 KB)"),
        "{text}"
    );
    assert!(interim.exists(), "a no keeps the file");
    let out = run(&dir, &["evidence", "purge-legacy"], "y\n", &[]);
    assert!(out.status.success());
    assert!(!interim.exists(), "a yes deletes it");
}
