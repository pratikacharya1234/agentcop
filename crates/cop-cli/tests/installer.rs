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
            .arg(subcommand)
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
    assert_eq!(hook["command"], sb.hook_path());
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
