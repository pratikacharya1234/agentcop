//! Hook-entry guard (C2-R3). Written in Rust, not TOML: deciding whether a full rewrite drops the
//! hook entry means reading the file on disk. The on/off switch, the marker and the protected files
//! live in `[hook_guard]` in the policy file (see `HookGuard`).
//!
//! PLAN:
//! 1. Switched off in the policy: no decision here.
//! 2. Edit and MultiEdit: deny when an old_string holds the marker (any change to that text).
//! 3. Write: deny when the file on disk holds the marker and the new content does not.
//! 4. Bash: deny when the command names the marker and writes a protected settings file.
//! 5. Only the protected project settings files are checked here. The global settings file is denied by the TOML rules.

use crate::HookGuard;
use cop_core::AgentEvent;

const REASON: &str = "Would remove or change the AgentCop hook entry in project settings";

/// Some(reason) when the change must be denied; None when the TOML rules decide.
pub fn hook_entry_change(
    guard: &HookGuard,
    event: &AgentEvent,
    bash_writes: &[&str],
) -> Option<&'static str> {
    if !guard.enabled {
        return None;
    }
    let input = &event.tool_input;
    let file = input["file_path"].as_str().unwrap_or("");
    let marker = guard.marker.as_str();
    let names_marker = |text: Option<&str>| text.is_some_and(|t| t.contains(marker));
    let protected = |path: &str| {
        guard
            .settings_files
            .iter()
            .any(|f| path.ends_with(f.as_str()))
    };
    let hit = match event.tool_name.as_str() {
        "Edit" => protected(file) && names_marker(input["old_string"].as_str()),
        "MultiEdit" => {
            protected(file)
                && input["edits"].as_array().is_some_and(|edits| {
                    edits.iter().any(|e| names_marker(e["old_string"].as_str()))
                })
        }
        "Write" => {
            protected(file)
                && std::fs::read_to_string(file).is_ok_and(|old| old.contains(marker))
                && !names_marker(input["content"].as_str())
        }
        name if name.eq_ignore_ascii_case("bash") => {
            names_marker(input["command"].as_str()) && bash_writes.iter().any(|w| protected(w))
        }
        _ => false,
    };
    hit.then_some(REASON)
}
