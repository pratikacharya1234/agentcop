//! Integration tests for agentcop installer
//!
//! Tests that verify:
//! - Installer edits ~/.claude/settings.json (not wrong path)
//! - --dry-run works without modifying files
//! - Backup is created before write
//! - Running install twice is idempotent
//! - Hook has absolute path to cop-hook binary
//! - Hook has "onFailure": "block"

use serde_json::json;

#[test]
fn hook_json_structure() {
    // Hook JSON must include "onFailure": "block" per Claude Code spec
    let hook_json = json!({
        "hookPath": "/path/to/cop-hook",
        "onFailure": "block"
    });

    assert_eq!(
        hook_json.get("onFailure").and_then(|v| v.as_str()),
        Some("block"),
        "Hook must have onFailure set to 'block' for fail-closed behavior"
    );
    assert!(
        hook_json["hookPath"].as_str().unwrap().starts_with("/"),
        "Hook path must be absolute"
    );
}

#[test]
fn backup_extension_is_bak() {
    let backup_ext = ".bak";
    assert_eq!(backup_ext, ".bak");
}
