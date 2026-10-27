//! FP-1 follow-up (2026-10-26, ADR 26): `agentcop install` keeps the user's `sensitive_files_extra` names when it
//! updates the policy, the same as the other settings it keeps.
use std::fs;
use std::io::Write;
use std::path::{Path, PathBuf};
use std::process::{Command, Output, Stdio};

const DEFAULT: &str = include_str!("../../../policy/default.toml");

fn sandbox(name: &str) -> PathBuf {
    let dir = PathBuf::from(env!("CARGO_TARGET_TMPDIR"))
        .join(format!("fp1x-{name}-{}", std::process::id()));
    let _ = fs::remove_dir_all(&dir);
    fs::create_dir_all(dir.join("home/.claude")).unwrap();
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

fn install(dir: &Path) -> Output {
    let mut child = Command::new(env!("CARGO_BIN_EXE_agentcop"))
        .arg("install")
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

#[test]
fn reinstall_keeps_the_users_extra_secret_names() {
    let dir = sandbox("keep");
    assert!(install(&dir).status.success());
    let policy = dir.join("home/.agentcop/policy.toml");
    fs::write(
        &policy,
        format!("sensitive_files_extra = [\"vault.json\"]\n{DEFAULT}"),
    )
    .unwrap();

    let out = install(&dir);
    assert!(
        out.status.success(),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
    let text = fs::read_to_string(&policy).unwrap();
    assert!(
        text.contains("sensitive_files_extra = [\"vault.json\"]"),
        "{text}"
    );
}
