//! Rule of Two: a session that reads untrusted input, touches sensitive data and takes an external action is frozen.
//!
//! PLAN:
//! 1. Rules come from policy/taint.toml. Empty sensitive or external lists are refused: the rule could never fire.
//! 2. classify(event): which of the three properties this one event adds. Bash read commands count as untrusted input.
//! 3. step(flags, event): once frozen, deny everything. Otherwise OR in the new flags. All three set = freeze.
//! 4. State is one JSON file per session. The file name is the SHA-256 of the session id (no path escape). A missing file means no flags. A corrupt file is an error.
//! 5. No session id uses the shared key "unknown". That is the conservative choice.

use cop_core::AgentEvent;
use regex::Regex;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::fs;
use std::path::PathBuf;

#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq, Eq)]
pub struct Flags {
    pub untrusted: bool,
    pub sensitive: bool,
    pub external: bool,
    pub frozen: bool,
    /// Absolute paths the agent created or changed this session (C2-R3: scripts it wrote ask).
    #[serde(default)]
    pub written: Vec<String>,
}

#[derive(Deserialize)]
struct RulesFile {
    untrusted_tools: Vec<String>,
    #[serde(default)]
    untrusted_bash: Vec<String>,
    sensitive: Vec<String>,
    #[serde(default)]
    sensitive_content: Vec<String>,
    external: Vec<String>,
}

#[derive(Debug)]
pub struct TaintRules {
    untrusted_tools: Vec<String>,
    untrusted_bash: Vec<Regex>,
    sensitive: Vec<Regex>,
    sensitive_content: Vec<Regex>,
    external: Vec<Regex>,
}

impl TaintRules {
    pub fn from_toml(text: &str) -> Result<Self, String> {
        let file: RulesFile = toml::from_str(text).map_err(|e| format!("bad taint rules: {e}"))?;
        if file.sensitive.is_empty() || file.external.is_empty() {
            return Err(
                "taint rules need sensitive and external patterns; refusing to start".to_string(),
            );
        }
        Ok(Self {
            untrusted_tools: file.untrusted_tools,
            untrusted_bash: compile(&file.untrusted_bash)?,
            sensitive: compile(&file.sensitive)?,
            sensitive_content: compile(&file.sensitive_content)?,
            external: compile(&file.external)?,
        })
    }
}

fn compile(patterns: &[String]) -> Result<Vec<Regex>, String> {
    patterns
        .iter()
        .map(|p| Regex::new(p).map_err(|e| format!("bad taint pattern {p}: {e}")))
        .collect()
}

/// What this one event adds.
///
/// PLAN (C2-R):
/// 1. Bash: judge what the command does. The patterns see the parsed action lines (exec, write, pipe),
///    so heredoc text and quoted strings do not count.
/// 2. Bash content patterns (secret-looking keys) still scan the raw command, because a key written into a file is still a key.
/// 3. A Bash command that cannot be parsed adds only the content flag. The judge denies it.
/// 4. Other tools: the raw tool name and input, as before. MCP tools always count as external.
pub fn classify(event: &AgentEvent, rules: &TaintRules) -> Flags {
    if event.tool_name.eq_ignore_ascii_case("Bash") {
        return classify_bash(event, rules);
    }
    let text = format!("{} {}", event.tool_name, event.tool_input);
    let untrusted = rules
        .untrusted_tools
        .iter()
        .any(|t| t.eq_ignore_ascii_case(&event.tool_name));
    let sensitive = rules.sensitive.iter().any(|re| re.is_match(&text))
        || rules.sensitive_content.iter().any(|re| re.is_match(&text));
    Flags {
        untrusted,
        sensitive,
        external: event.tool_name.starts_with("mcp__"),
        frozen: false,
        written: written_by_tool(event),
    }
}

/// File-edit tools name the file they change in `file_path`.
fn written_by_tool(event: &AgentEvent) -> Vec<String> {
    const EDIT_TOOLS: [&str; 3] = ["Write", "Edit", "MultiEdit"];
    if !EDIT_TOOLS.contains(&event.tool_name.as_str()) {
        return Vec::new();
    }
    event.tool_input["file_path"]
        .as_str()
        .map(|p| vec![absolute(p)])
        .unwrap_or_default()
}

/// Absolute form of a path, from the hook's working directory.
fn absolute(raw: &str) -> String {
    let cwd = std::env::current_dir().unwrap_or_default();
    cop_core::absolute_path(raw, &cwd)
}

fn classify_bash(event: &AgentEvent, rules: &TaintRules) -> Flags {
    let command = event.tool_input["command"].as_str().unwrap_or("");
    let content = rules
        .sensitive_content
        .iter()
        .any(|re| re.is_match(command));
    let analysis = cop_shell::analyze(command);
    if analysis.unparsed {
        return Flags {
            sensitive: content,
            ..Flags::default()
        };
    }
    let actions = analysis.actions.join("\n");
    let written = analysis
        .actions
        .iter()
        .filter_map(|a| a.strip_prefix("write "))
        .map(absolute)
        .collect();
    Flags {
        untrusted: rules.untrusted_bash.iter().any(|re| re.is_match(&actions)),
        sensitive: content || rules.sensitive.iter().any(|re| re.is_match(&actions)),
        external: rules.external.iter().any(|re| re.is_match(&actions)),
        frozen: false,
        written,
    }
}

/// Apply one event to the session's flags. Returns the new flags and a deny reason, if the event must be denied.
pub fn step(before: Flags, event: &AgentEvent, rules: &TaintRules) -> (Flags, Option<String>) {
    if before.frozen {
        return (
            before.clone(),
            Some("session is frozen by Rule of Two".to_string()),
        );
    }
    let added = classify(event, rules);
    let mut written = before.written.clone();
    for path in added.written {
        if !written.contains(&path) {
            written.push(path);
        }
    }
    let after = Flags {
        untrusted: before.untrusted || added.untrusted,
        sensitive: before.sensitive || added.sensitive,
        external: before.external || added.external,
        frozen: false,
        written,
    };
    if after.untrusted && after.sensitive && after.external {
        let frozen = Flags {
            frozen: true,
            ..after.clone()
        };
        return (frozen, Some("Rule of Two: untrusted input, sensitive data and an external action in one session".to_string()));
    }
    (after, None)
}

pub struct SessionStore {
    pub dir: PathBuf,
}

impl SessionStore {
    fn file_for(&self, session_id: Option<&str>) -> PathBuf {
        let digest = Sha256::digest(session_id.unwrap_or("unknown").as_bytes());
        self.dir.join(format!("{digest:x}.json"))
    }

    pub fn load(&self, session_id: Option<&str>) -> Result<Flags, String> {
        let path = self.file_for(session_id);
        if !path.exists() {
            return Ok(Flags::default());
        }
        let text = fs::read_to_string(&path).map_err(|e| format!("read session state: {e}"))?;
        serde_json::from_str(&text).map_err(|e| format!("session state is corrupt: {e}"))
    }

    pub fn save(&self, session_id: Option<&str>, flags: Flags) -> Result<(), String> {
        fs::create_dir_all(&self.dir).map_err(|e| format!("create session dir: {e}"))?;
        let path = self.file_for(session_id);
        let tmp = path.with_extension("tmp");
        let text = serde_json::to_string(&flags).map_err(|e| e.to_string())?;
        fs::write(&tmp, text).map_err(|e| format!("write session state: {e}"))?;
        fs::rename(&tmp, &path).map_err(|e| format!("replace session state: {e}"))
    }
}
