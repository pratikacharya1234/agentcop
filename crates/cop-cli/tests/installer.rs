//! Installer tests: run the BUILT agentcop binary in a temp HOME, against a realistic settings.json.
//!
//! Checks:
//! - install writes exactly {"hooks":{"PreToolUse":[{"matcher":"*","hooks":[{...}]}]}}
//! - no "hookPath", no top-level "PreToolUse" key
//! - other keys and existing hook groups are kept, in the same order
//! - install twice = identical file
//! - uninstall = byte-identical to the original
//! - install copies the default policy to ~/.agentcop/policy.toml

use serde_json::Value;
use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::atomic::{AtomicUsize, Ordering};

static COUNTER: AtomicUsize = AtomicUsize::new(0);

/// A realistic ~/.claude/settings.json: plugins, model, permissions, and a SessionStart hook.
const REALISTIC_SETTINGS: &str = r#"{
  "permissions": {
    "defaultMode": "auto"
  },
  "model": "sonnet",
  "enabledPlugins": {
    "rust-analyzer-lsp@claude-plugins-official": true
  },
  "hooks": {
    "SessionStart": [
      {
        "matcher": "startup",
        "hooks": [
          {
            "type": "command",
            "command": "echo hello"
          }
        ]
      }
    ],
    "PreToolUse": [
      {
        "matcher": "Write",
        "hooks": [
          {
            "type": "command",
            "command": "echo existing-pre-tool-use"
          }
        ]
      }
    ]
  },
  "theme": "dark"
}
"#;

struct Sandbox {
    root: PathBuf,
}

impl Sandbox {
    fn new() -> Self {
        let n = COUNTER.fetch_add(1, Ordering::SeqCst);
        let root =
            std::env::temp_dir().join(format!("agentcop-install-{}-{}", std::process::id(), n));
        let _ = fs::remove_dir_all(&root);
        fs::create_dir_all(root.join("home/.claude")).unwrap();
        fs::create_dir_all(root.join("work")).unwrap();
        fs::write(root.join("home/.claude/settings.json"), REALISTIC_SETTINGS).unwrap();
        Sandbox { root }
    }

    fn home(&self) -> PathBuf {
        self.root.join("home")
    }

    fn settings(&self) -> PathBuf {
        self.home().join(".claude/settings.json")
    }

    fn backup(&self) -> PathBuf {
        self.home().join(".claude/settings.json.bak")
    }

    /// Canonical absolute path to a stand-in cop-hook file (the installer never runs it).
    fn hook_path(&self) -> String {
        let hook = self.root.join("bin/cop-hook");
        fs::create_dir_all(hook.parent().unwrap()).unwrap();
        fs::write(&hook, b"").unwrap();
        fs::canonicalize(&hook)
            .unwrap()
            .to_string_lossy()
            .into_owned()
    }

    fn run(&self, subcommand: &str) -> std::process::Output {
        self.run_with_hook(subcommand, &self.hook_path())
    }

    fn run_with_hook(&self, subcommand: &str, hook: &str) -> std::process::Output {
        Command::new(env!("CARGO_BIN_EXE_agentcop"))
            .args(subcommand.split_whitespace())
            .env_clear()
            .env("HOME", self.home())
            .env("AGENTCOP_HOOK", hook)
            .current_dir(self.root.join("work"))
            .output()
            .expect("failed to run agentcop")
    }

    fn settings_json(&self) -> Value {
        serde_json::from_str(&fs::read_to_string(self.settings()).unwrap()).unwrap()
    }
}

impl Drop for Sandbox {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.root);
    }
}

fn assert_success(out: &std::process::Output) {
    assert!(
        out.status.success(),
        "agentcop failed: {}",
        String::from_utf8_lossy(&out.stderr)
    );
}

#[test]
fn install_writes_claude_code_hook_shape() {
    let sb = Sandbox::new();
    assert_success(&sb.run("install"));

    let s = sb.settings_json();
    assert!(s.get("PreToolUse").is_none(), "no top-level PreToolUse key");

    let groups = s["hooks"]["PreToolUse"]
        .as_array()
        .expect("hooks.PreToolUse array");
    let ours = groups.last().expect("our group appended");
    assert_eq!(ours["matcher"], "*");
    let hook = &ours["hooks"][0];
    assert_eq!(hook["type"], "command");
    // 2026-10-27: settings point at the installed copy, never at the file we copied from.
    assert_eq!(
        hook["command"],
        sb.home().join(".agentcop/bin/cop-hook").to_str().unwrap()
    );
    assert_eq!(hook["onFailure"], "block");
    assert!(hook.get("hookPath").is_none(), "no hookPath key");
}

#[test]
fn install_keeps_other_keys_and_existing_hooks() {
    let sb = Sandbox::new();
    assert_success(&sb.run("install"));

    let s = sb.settings_json();
    assert_eq!(s["model"], "sonnet");
    assert_eq!(s["theme"], "dark");
    assert_eq!(s["permissions"]["defaultMode"], "auto");
    assert_eq!(
        s["enabledPlugins"]["rust-analyzer-lsp@claude-plugins-official"],
        true
    );
    assert_eq!(
        s["hooks"]["SessionStart"][0]["hooks"][0]["command"],
        "echo hello"
    );

    let groups = s["hooks"]["PreToolUse"].as_array().unwrap();
    assert_eq!(
        groups.len(),
        2,
        "existing PreToolUse group kept, ours appended"
    );
    assert_eq!(
        groups[0]["hooks"][0]["command"],
        "echo existing-pre-tool-use"
    );
}

#[test]
fn install_keeps_top_level_key_order() {
    let sb = Sandbox::new();
    assert_success(&sb.run("install"));

    let text = fs::read_to_string(sb.settings()).unwrap();
    let pos = |key: &str| text.find(key).unwrap_or_else(|| panic!("{key} missing"));
    assert!(pos("\"permissions\"") < pos("\"model\""));
    assert!(pos("\"model\"") < pos("\"enabledPlugins\""));
    assert!(pos("\"enabledPlugins\"") < pos("\"hooks\""));
    assert!(pos("\"hooks\"") < pos("\"theme\""));
}

#[test]
fn install_twice_gives_identical_file() {
    let sb = Sandbox::new();
    assert_success(&sb.run("install"));
    let first = fs::read(sb.settings()).unwrap();
    assert_success(&sb.run("install"));
    let second = fs::read(sb.settings()).unwrap();
    assert_eq!(first, second, "second install must change nothing");
}

#[test]
fn uninstall_restores_byte_identical_original() {
    let sb = Sandbox::new();
    assert_success(&sb.run("install"));
    assert_success(&sb.run("uninstall"));
    let restored = fs::read_to_string(sb.settings()).unwrap();
    assert_eq!(
        restored, REALISTIC_SETTINGS,
        "uninstall must restore the original bytes"
    );
    assert!(
        Path::new(&sb.backup()).exists(),
        "backup is kept after restore"
    );
}

#[test]
fn install_copies_default_policy_to_home() {
    let sb = Sandbox::new();
    assert_success(&sb.run("install"));
    let installed = sb.home().join(".agentcop/policy.toml");
    let text = fs::read_to_string(&installed).expect("policy installed");
    assert!(text.contains("[[rules]]"), "installed policy has rules");
}

#[test]
fn install_refuses_missing_hook_and_leaves_settings_untouched() {
    let sb = Sandbox::new();
    let before = fs::read(sb.settings()).unwrap();
    let out = sb.run_with_hook("install", "/nonexistent/dir/cop-hook");
    assert!(
        !out.status.success(),
        "install must fail when cop-hook is missing"
    );
    assert_eq!(
        fs::read(sb.settings()).unwrap(),
        before,
        "settings must not change"
    );
    assert!(!sb.backup().exists(), "no backup written on failure");
}

// 2026-10-27 (item 3, install hygiene). The live hook is a copy in ~/.agentcop/bin.

fn mode(path: &Path) -> u32 {
    use std::os::unix::fs::PermissionsExt;
    fs::metadata(path).unwrap().permissions().mode() & 0o777
}

#[test]
fn install_copies_the_hook_to_bin_as_a_program() {
    let sb = Sandbox::new();
    assert_success(&sb.run("install"));
    let bin = sb.home().join(".agentcop/bin/cop-hook");
    assert!(bin.exists(), "the copy exists");
    assert_eq!(mode(&bin), 0o700, "the copy is a program: 0700");
    assert_eq!(
        mode(&sb.home().join(".agentcop")),
        0o700,
        "state folder 0700"
    );
    assert_eq!(
        mode(&sb.home().join(".agentcop/bin")),
        0o700,
        "bin folder 0700"
    );
}

#[test]
fn install_never_points_settings_at_a_build_directory() {
    let sb = Sandbox::new();
    // The stand-in lives under target/debug, as a development build would.
    let stand_in = sb.root.join("target/debug/cop-hook");
    fs::create_dir_all(stand_in.parent().unwrap()).unwrap();
    fs::write(&stand_in, b"#!/bin/sh\nexit 0\n").unwrap();
    assert_success(&sb.run_with_hook("install", stand_in.to_str().unwrap()));
    let s = sb.settings_json();
    let command = s["hooks"]["PreToolUse"][0]["hooks"][0]["command"]
        .as_str()
        .unwrap();
    assert!(
        !command.contains("/target/"),
        "settings must not point at a build directory: {command}"
    );
}

#[test]
fn install_tightens_existing_state_to_explicit_modes() {
    use std::os::unix::fs::PermissionsExt;
    let sb = Sandbox::new();
    let state = sb.home().join(".agentcop");
    fs::create_dir_all(&state).unwrap();
    fs::set_permissions(&state, fs::Permissions::from_mode(0o775)).unwrap();
    fs::write(state.join("decisions.jsonl"), "").unwrap();
    fs::set_permissions(
        state.join("decisions.jsonl"),
        fs::Permissions::from_mode(0o644),
    )
    .unwrap();
    assert_success(&sb.run("install"));
    assert_eq!(mode(&state), 0o700);
    assert_eq!(mode(&state.join("policy.toml")), 0o600);
}

#[test]
fn install_keeps_custom_policy_rules_and_mode_and_backs_up() {
    let sb = Sandbox::new();
    let state = sb.home().join(".agentcop");
    fs::create_dir_all(&state).unwrap();
    fs::write(
        state.join("policy.toml"),
        "mode = \"log-only\"\n\n[[rules]]\npattern = \"my-internal-deploy\"\nverdict = \"deny\"\nreason = \"Mine\"\n",
    )
    .unwrap();
    let out = sb.run("install");
    assert_success(&out);
    let text = fs::read_to_string(state.join("policy.toml")).unwrap();
    assert!(
        text.contains("mode = \"log-only\""),
        "the user's mode is kept"
    );
    assert!(
        text.contains("my-internal-deploy"),
        "the user's custom rule is kept"
    );
    assert!(text.contains("[[rules]]"), "the new default rules are in");
    assert_eq!(mode(&state.join("policy.toml")), 0o600);
    let backups: Vec<_> = fs::read_dir(&state)
        .unwrap()
        .filter_map(|e| e.ok().map(|e| e.file_name().to_string_lossy().into_owned()))
        .filter(|n| n.starts_with("policy.toml.bak-"))
        .collect();
    assert_eq!(backups.len(), 1, "the old policy is backed up");
    assert!(
        String::from_utf8_lossy(&out.stdout).contains("policy diff"),
        "a diff is shown"
    );
}

#[test]
fn install_imports_legacy_json_into_state_db_and_archives_it() {
    let sb = Sandbox::new();
    let state = sb.home().join(".agentcop");
    fs::create_dir_all(state.join("sessions")).unwrap();
    fs::write(
        state.join("sessions/abc123.json"),
        r#"{"frozen":false,"untrusted":false,"sensitive":false,"external":false}"#,
    )
    .unwrap();
    fs::write(
        state.join("decisions.jsonl"),
        "{\"seq\":1,\"case_id\":\"CASE-aaaaaaaaaaaa\",\"action\":\"convict\",\"at\":\"2026-10-23T00:00:00Z\",\"prev\":\"0\",\"hash\":\"h1\"}\n",
    )
    .unwrap();
    assert_success(&sb.run("install"));
    assert!(
        !state.join("sessions").exists(),
        "legacy sessions moved away"
    );
    assert!(
        !state.join("decisions.jsonl").exists(),
        "legacy decisions moved away"
    );
    assert!(state.join("legacy/sessions/abc123.json").exists());
    assert!(state.join("legacy/decisions.jsonl").exists());
    let store = cop_taint::SessionStore::open(&state.join("state.db")).unwrap();
    assert_eq!(
        store.legacy_session_count().unwrap(),
        1,
        "the session row is imported"
    );
    assert_eq!(
        store.decision_count().unwrap(),
        1,
        "the decision row is imported"
    );
}

#[test]
fn install_dry_run_changes_nothing() {
    let sb = Sandbox::new();
    let before = fs::read(sb.settings()).unwrap();
    assert_success(&sb.run("install --dry-run"));
    assert_eq!(
        fs::read(sb.settings()).unwrap(),
        before,
        "settings unchanged"
    );
    assert!(!sb.home().join(".agentcop").exists(), "nothing created");
}

#[test]
fn install_re_points_an_old_build_path() {
    let sb = Sandbox::new();
    let old = sb.root.join("target/debug/cop-hook");
    fs::create_dir_all(old.parent().unwrap()).unwrap();
    fs::write(&old, b"").unwrap();
    let mut settings: Value = serde_json::from_str(REALISTIC_SETTINGS).unwrap();
    settings["hooks"]["PreToolUse"]
        .as_array_mut()
        .unwrap()
        .push(serde_json::json!({"matcher":"*","hooks":[{"type":"command","command": old.to_str().unwrap(),"onFailure":"block"}]}));
    fs::write(
        sb.settings(),
        serde_json::to_string_pretty(&settings).unwrap(),
    )
    .unwrap();
    assert_success(&sb.run("install"));
    let text = fs::read_to_string(sb.settings()).unwrap();
    assert!(
        !text.contains("/target/debug/cop-hook"),
        "old build path replaced"
    );
    assert!(text.contains(".agentcop/bin/cop-hook"));
}
