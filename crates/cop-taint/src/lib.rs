//! Rule of Two: a session that reads untrusted input, touches sensitive data and takes an external action is frozen.
//!
//! Semantics (owner, 2026-10-27):
//! 1. Untrusted input is external data only: web fetch and search results, MCP results, downloads (curl, wget),
//!    and files inside a repo the session cloned. Local reads, greps and listings are not untrusted.
//! 2. External actions are network and send actions: web tools, MCP calls, curl, wget, git push and clone, publish.
//! 3. A frozen session blocks only external actions. Local work continues. The hook decides that, using `classify`.
//! 4. The freeze is recorded once: one trigger record and a counter of blocked calls. No auto-expiry.
//!    `release` clears it, and only a person runs it (`agentcop release <session>`).
//! 5. State is one JSON file per session. The file name is the SHA-256 of the session id (no path escape).
//!    A missing file means no flags. A corrupt file is an error. No session id uses the shared key "unknown".

use cop_core::AgentEvent;
use regex::Regex;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::fs;
use std::path::{Path, PathBuf};

/// The reason written when all three properties are present.
pub const TRIGGER_REASON: &str =
    "Rule of Two: untrusted input, sensitive data and an external action in one session";

/// Commands that print a file's contents. Their file arguments are checked against cloned repos.
const READ_COMMANDS: [&str; 9] = [
    "cat", "head", "tail", "less", "more", "grep", "rg", "jq", "sed",
];

#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq, Eq)]
pub struct Flags {
    pub untrusted: bool,
    pub sensitive: bool,
    pub external: bool,
    pub frozen: bool,
    /// Absolute paths the agent created or changed this session (C2-R3: scripts it wrote ask).
    #[serde(default)]
    pub written: Vec<String>,
    /// Absolute directories of repos this session cloned. Files inside them are untrusted input.
    #[serde(default)]
    pub foreign: Vec<String>,
    /// The record of the freeze, when frozen.
    #[serde(default)]
    pub freeze: Option<Freeze>,
}

/// One freeze: its trigger, the evidence record that names it, and how many external calls it blocked.
#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq, Eq)]
pub struct Freeze {
    pub trigger: String,
    /// `CASE-<12 hex>` of the trigger's evidence row. Empty until the hook has written it.
    pub case: String,
    pub blocked: u64,
}

#[derive(Deserialize)]
struct RulesFile {
    untrusted_tools: Vec<String>,
    #[serde(default)]
    external_tools: Vec<String>,
    #[serde(default)]
    read_tools: Vec<String>,
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
    external_tools: Vec<String>,
    read_tools: Vec<String>,
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
            external_tools: file.external_tools,
            read_tools: file.read_tools,
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

/// What this one event adds, with no session history.
pub fn classify(event: &AgentEvent, rules: &TaintRules) -> Flags {
    classify_with(event, rules, &[])
}

/// What this one event adds. `foreign` lists the cloned-repo directories of the session.
///
/// PLAN:
/// 1. Bash: the parsed action lines (exec, write, pipe) are matched. Heredoc text and quotes do not count.
/// 2. Other tools: the tool name and input. Web and MCP tools are untrusted and external.
/// 3. Reads inside a cloned repo are untrusted. Reads anywhere else are not.
/// 4. Sensitive content patterns (secret-looking keys) scan the raw command, because a key in a file is still a key.
/// 5. A Bash command that cannot be parsed adds only the content flag. The judge denies it.
pub fn classify_with(event: &AgentEvent, rules: &TaintRules, foreign: &[String]) -> Flags {
    let cwd = cop_core::event_cwd(event);
    if event.tool_name.eq_ignore_ascii_case("Bash") {
        return classify_bash(event, rules, foreign, &cwd);
    }
    classify_tool(event, rules, foreign, &cwd)
}

fn classify_tool(event: &AgentEvent, rules: &TaintRules, foreign: &[String], cwd: &Path) -> Flags {
    let tool = event.tool_name.as_str();
    let text = format!("{} {}", tool, event.tool_input);
    let is_mcp = tool.starts_with("mcp__");
    let in_list = |list: &[String]| list.iter().any(|t| t.eq_ignore_ascii_case(tool));
    let reads_foreign = in_list(&rules.read_tools)
        && path_field(event).is_some_and(|p| under_any(&cop_core::absolute_path(p, cwd), foreign));
    let untrusted = is_mcp || in_list(&rules.untrusted_tools) || reads_foreign;
    let external = is_mcp || in_list(&rules.external_tools);
    let sensitive = rules.sensitive.iter().any(|re| re.is_match(&text))
        || rules.sensitive_content.iter().any(|re| re.is_match(&text));
    Flags {
        untrusted,
        sensitive,
        external,
        written: written_by_tool(event, cwd),
        ..Flags::default()
    }
}

/// The path a read or edit tool names: `file_path`, or `path` for search tools.
fn path_field(event: &AgentEvent) -> Option<&str> {
    event.tool_input["file_path"]
        .as_str()
        .or_else(|| event.tool_input["path"].as_str())
}

/// File-edit tools name the file they change in `file_path`.
fn written_by_tool(event: &AgentEvent, cwd: &Path) -> Vec<String> {
    const EDIT_TOOLS: [&str; 3] = ["Write", "Edit", "MultiEdit"];
    if !EDIT_TOOLS.contains(&event.tool_name.as_str()) {
        return Vec::new();
    }
    event.tool_input["file_path"]
        .as_str()
        .map(|p| vec![cop_core::absolute_path(p, cwd)])
        .unwrap_or_default()
}

fn under_any(path: &str, dirs: &[String]) -> bool {
    dirs.iter()
        .any(|d| path == d || path.starts_with(&format!("{d}/")))
}

fn classify_bash(event: &AgentEvent, rules: &TaintRules, foreign: &[String], cwd: &Path) -> Flags {
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
        .map(|p| cop_core::absolute_path(p, cwd))
        .collect();
    let foreign_new = clone_dirs(&analysis.actions, cwd);
    Flags {
        untrusted: rules.untrusted_bash.iter().any(|re| re.is_match(&actions))
            || reads_foreign(&analysis.actions, foreign, cwd),
        sensitive: content || rules.sensitive.iter().any(|re| re.is_match(&actions)),
        external: rules.external.iter().any(|re| re.is_match(&actions)),
        written,
        foreign: foreign_new,
        ..Flags::default()
    }
}

/// True when a read command names a file inside a cloned repo.
fn reads_foreign(actions: &[String], foreign: &[String], cwd: &Path) -> bool {
    actions.iter().any(|line| {
        let Some(words) = line.strip_prefix("exec ") else {
            return false;
        };
        let words: Vec<&str> = words.split_whitespace().collect();
        let name = words[0].rsplit('/').next().unwrap_or("");
        READ_COMMANDS.contains(&name)
            && words[1..]
                .iter()
                .filter(|w| !w.starts_with('-'))
                .any(|w| under_any(&cop_core::absolute_path(w, cwd), foreign))
    })
}

/// Directories a `git clone` creates: the second word if given, else the repo name from the URL.
fn clone_dirs(actions: &[String], cwd: &Path) -> Vec<String> {
    actions
        .iter()
        .filter_map(|line| {
            let words: Vec<&str> = line.strip_prefix("exec ")?.split_whitespace().collect();
            if words.len() < 3 || words[0] != "git" || words[1] != "clone" {
                return None;
            }
            let operands: Vec<&str> = words[2..]
                .iter()
                .copied()
                .filter(|w| !w.starts_with('-'))
                .collect();
            let dir = match operands.get(1) {
                Some(dir) => dir.to_string(),
                None => operands
                    .first()?
                    .trim_end_matches('/')
                    .rsplit('/')
                    .next()?
                    .trim_end_matches(".git")
                    .to_string(),
            };
            Some(cop_core::absolute_path(&dir, cwd))
        })
        .collect()
}

fn merge(into: &mut Vec<String>, more: Vec<String>) {
    for item in more {
        if !into.contains(&item) {
            into.push(item);
        }
    }
}

/// Apply one event to the session's flags. Returns the new flags, and the trigger reason
/// when this event completed the three properties (the freeze happens once).
pub fn step(before: Flags, event: &AgentEvent, rules: &TaintRules) -> (Flags, Option<String>) {
    let added = classify_with(event, rules, &before.foreign);
    let mut after = before;
    after.untrusted |= added.untrusted;
    after.sensitive |= added.sensitive;
    after.external |= added.external;
    merge(&mut after.written, added.written);
    merge(&mut after.foreign, added.foreign);
    if after.frozen || !(after.untrusted && after.sensitive && after.external) {
        return (after, None);
    }
    after.frozen = true;
    after.freeze = Some(Freeze {
        trigger: TRIGGER_REASON.to_string(),
        case: String::new(),
        blocked: 0,
    });
    (after, Some(TRIGGER_REASON.to_string()))
}

/// What a release cleared.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Released {
    pub trigger: String,
    pub case: String,
    pub blocked: u64,
    pub by: String,
    pub at: String,
}

/// Release a frozen session: clear the freeze and the three flags. The next external action is then
/// judged normally (a push asks), not denied again. Returns None when the session was not frozen.
pub fn release(
    store: &SessionStore,
    session: Option<&str>,
    by: &str,
    at: &str,
) -> Result<Option<Released>, String> {
    let mut flags = store.load(session)?;
    if !flags.frozen {
        return Ok(None);
    }
    let freeze = flags.freeze.take().unwrap_or_default();
    flags.frozen = false;
    flags.untrusted = false;
    flags.sensitive = false;
    flags.external = false;
    store.save(session, flags)?;
    Ok(Some(Released {
        trigger: freeze.trigger,
        case: freeze.case,
        blocked: freeze.blocked,
        by: by.to_string(),
        at: at.to_string(),
    }))
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
