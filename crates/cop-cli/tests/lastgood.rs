//! Item 4b (2026-10-26): install saves the last-known-good policy, and doctor names a failing canary and the
//! policy the hook is running instead. Each case runs the built agentcop in its own temp HOME.
use std::fs;
use std::io::Write;
use std::path::{Path, PathBuf};
use std::process::{Command, Output, Stdio};

const DEFAULT: &str = include_str!("../../../policy/default.toml");

/// The shipped policy with the rm rule mangled, so `rm -rf /` is not caught by the rule.
fn broken_rm() -> String {
    let broken = DEFAULT.replacen("'''rm\\s+", "'''zz\\s+", 1);
    assert_ne!(broken, DEFAULT);
    broken
}

fn sandbox(name: &str) -> PathBuf {
    let dir = PathBuf::from(env!("CARGO_TARGET_TMPDIR"))
        .join(format!("lastgood-{name}-{}", std::process::id()));
    let _ = fs::remove_dir_all(&dir);
    fs::create_dir_all(dir.join("home/.claude")).unwrap();
    fs::create_dir_all(dir.join("home/.agentcop")).unwrap();
    fs::create_dir_all(dir.join("work")).unwrap();
    fs::write(
        dir.join("home/.claude/settings.json"),
        r#"{"model":"sonnet"}"#,
    )
    .unwrap();
    let hook = dir.join("stand-in-cop-hook");
    fs::write(
        &hook,
        "#!/bin/sh\nif [ \"$1\" = \"--version\" ]; then echo \"cop-hook 0.0.1\"; fi\nexit 0\n",
    )
    .unwrap();
    fs::set_permissions(&hook, std::os::unix::fs::PermissionsExt::from_mode(0o755)).unwrap();
    dir
}

fn run(dir: &Path, args: &[&str]) -> Output {
    let mut child = Command::new(env!("CARGO_BIN_EXE_agentcop"))
        .args(args)
        .env_clear()
        .env("HOME", dir.join("home"))
        .env("AGENTCOP_HOOK", dir.join("stand-in-cop-hook"))
        .current_dir(dir.join("work"))
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    child.stdin.take().unwrap().write_all(b"").unwrap();
    child.wait_with_output().unwrap()
}

fn put_policy(dir: &Path, text: &str) {
    fs::write(dir.join("home/.agentcop/policy.toml"), text).unwrap();
}

#[test]
fn install_saves_the_passing_policy_as_last_known_good() {
    let dir = sandbox("install");
    let out = run(&dir, &["install"]);
    assert!(
        out.status.success(),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
    let saved = fs::read_to_string(dir.join("home/.agentcop/policy.lastgood.toml")).unwrap();
    assert_eq!(saved, DEFAULT);
}

#[test]
fn doctor_names_the_failing_canary_and_the_last_known_good_fallback() {
    let dir = sandbox("fallback");
    put_policy(&dir, &broken_rm());
    fs::write(dir.join("home/.agentcop/policy.lastgood.toml"), DEFAULT).unwrap();

    let out = run(&dir, &["doctor"]);
    let text = String::from_utf8_lossy(&out.stdout).to_string();
    assert!(
        text.contains(
            "FAIL  live policy fails canary rm -rf /; running last-known-good; fix your policy or run agentcop install"
        ),
        "{text}"
    );
    assert_eq!(out.status.code(), Some(1));
}

#[test]
fn doctor_says_built_in_defaults_when_there_is_no_last_known_good() {
    let dir = sandbox("builtin");
    put_policy(&dir, &broken_rm());

    let text = String::from_utf8_lossy(&run(&dir, &["doctor"]).stdout).to_string();
    assert!(
        text.contains("FAIL  live policy fails canary rm -rf /; running built-in defaults;"),
        "{text}"
    );
}

#[test]
fn doctor_passes_the_canaries_again_once_the_policy_is_fixed() {
    let dir = sandbox("fixed");
    put_policy(&dir, &broken_rm());
    put_policy(&dir, DEFAULT);

    let text = String::from_utf8_lossy(&run(&dir, &["doctor"]).stdout).to_string();
    assert!(
        text.contains("PASS  policy canaries: every must-catch action is caught"),
        "{text}"
    );
    assert!(!text.contains("fails canary"), "{text}");
}
