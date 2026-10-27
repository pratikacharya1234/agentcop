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
use rusqlite::{Connection, TransactionBehavior};
use serde::{Deserialize, Serialize};
use std::path::{Path, PathBuf};
use std::time::Duration;

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
    /// Unix seconds of the session's latest SessionStart heartbeat (FP-1). A script not changed since then may run
    /// after a secret read. None until the hook has seen a SessionStart for this session.
    #[serde(default)]
    pub started: Option<u64>,
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
    network_tools: Vec<String>,
    #[serde(default)]
    mcp_send_patterns: Vec<String>,
    #[serde(default)]
    read_tools: Vec<String>,
    #[serde(default)]
    untrusted_bash: Vec<String>,
    #[serde(default)]
    network_commands: Vec<String>,
    #[serde(default)]
    sensitive_content: Vec<String>,
    external: Vec<String>,
}

#[derive(Debug)]
pub struct TaintRules {
    network_commands: Vec<String>,
    untrusted_tools: Vec<String>,
    external_tools: Vec<String>,
    network_tools: Vec<String>,
    mcp_send_patterns: Vec<Regex>,
    read_tools: Vec<String>,
    untrusted_bash: Vec<Regex>,
    sensitive_content: Vec<Regex>,
    external: Vec<Regex>,
    /// The policy's extra secret file names (ADR 26). Set by the hook with `with_extra_secret_names`.
    extra_secret_names: Vec<String>,
}

impl TaintRules {
    /// Add the policy's extra secret file names. They only add to the built-in names.
    pub fn with_extra_secret_names(mut self, names: Vec<String>) -> Self {
        self.extra_secret_names = names;
        self
    }

    pub fn from_toml(text: &str) -> Result<Self, String> {
        let file: RulesFile = toml::from_str(text).map_err(|e| format!("bad taint rules: {e}"))?;
        if file.external.is_empty() {
            return Err("taint rules need external patterns; refusing to start".to_string());
        }
        Ok(Self {
            untrusted_tools: file.untrusted_tools,
            external_tools: file.external_tools,
            network_tools: file.network_tools,
            mcp_send_patterns: compile(&file.mcp_send_patterns)?,
            read_tools: file.read_tools,
            network_commands: file.network_commands,
            untrusted_bash: compile(&file.untrusted_bash)?,
            sensitive_content: compile(&file.sensitive_content)?,
            external: compile(&file.external)?,
            extra_secret_names: Vec::new(),
        })
    }
}

/// True when a key-shaped pattern matches `text`, except a documented example key (FP-1 follow-up, ADR 27): the
/// AWS documentation key and any key whose match ends in `EXAMPLE`. A real-looking key still matches.
fn key_in_text(patterns: &[Regex], text: &str) -> bool {
    patterns
        .iter()
        .any(|re| re.find_iter(text).any(|m| !m.as_str().ends_with("EXAMPLE")))
}

fn compile(patterns: &[String]) -> Result<Vec<Regex>, String> {
    patterns
        .iter()
        .map(|p| Regex::new(p).map_err(|e| format!("bad taint pattern {p}: {e}")))
        .collect()
}

/// What this one event adds, with no session history.
pub fn classify(event: &AgentEvent, rules: &TaintRules) -> Flags {
    classify_with(event, rules, &Flags::default())
}

/// What this one event adds. `foreign` lists the cloned-repo directories of the session.
///
/// PLAN:
/// 1. Bash: the parsed action lines (exec, write, pipe) are matched. Heredoc text and quotes do not count.
/// 2. Other tools: the tool name and input. Web and MCP tools are untrusted and external.
/// 3. Reads inside a cloned repo are untrusted. Reads anywhere else are not.
/// 4. Sensitive content patterns (secret-looking keys) scan the raw command, because a key in a file is still a key.
/// 5. A Bash command that cannot be parsed adds only the content flag. The judge denies it.
pub fn classify_with(event: &AgentEvent, rules: &TaintRules, session: &Flags) -> Flags {
    let foreign = &session.foreign[..];
    let cwd = cop_core::event_cwd(event);
    if event.tool_name.eq_ignore_ascii_case("Bash") {
        return classify_bash(event, rules, foreign, &cwd, session.sensitive);
    }
    classify_tool(event, rules, session, &cwd)
}

fn classify_tool(event: &AgentEvent, rules: &TaintRules, session: &Flags, cwd: &Path) -> Flags {
    let foreign = &session.foreign[..];
    let tool = event.tool_name.as_str();
    let text = format!("{} {}", tool, event.tool_input);
    let is_mcp = tool.starts_with("mcp__");
    let in_list = |list: &[String]| list.iter().any(|t| t.eq_ignore_ascii_case(tool));
    let reads_foreign = in_list(&rules.read_tools)
        && path_field(event).is_some_and(|p| under_any(&cop_core::absolute_path(p, cwd), foreign));
    let untrusted = is_mcp || in_list(&rules.untrusted_tools) || reads_foreign;
    // A secret is a file by name (FP-1). Text in a tool's content or search pattern is not a file.
    let sensitive = path_field(event)
        .is_some_and(|p| cop_shell::is_secret_with(p, &rules.extra_secret_names))
        || key_in_text(&rules.sensitive_content, &text);
    // A secret in the session, or in this call, makes any way of sending it out an external action:
    // web requests (the URL carries the data) and MCP tools that send, post or write.
    let holds_secret = session.sensitive || sensitive;
    let mcp_sends = is_mcp
        && rules
            .mcp_send_patterns
            .iter()
            .any(|re| re.is_match(&tool.to_lowercase()));
    let external = in_list(&rules.external_tools)
        || (in_list(&rules.network_tools) && holds_secret)
        || (is_mcp && (mcp_sends || holds_secret));
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

fn classify_bash(
    event: &AgentEvent,
    rules: &TaintRules,
    foreign: &[String],
    cwd: &Path,
    session_sensitive: bool,
) -> Flags {
    let command = event.tool_input["command"].as_str().unwrap_or("");
    let content = key_in_text(&rules.sensitive_content, command);
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
    let sensitive = content
        || cop_shell::file_operands(&analysis.actions)
            .iter()
            .any(|f| cop_shell::is_secret_with(f, &rules.extra_secret_names));
    // Once the session has touched sensitive data, every outbound request is an external action,
    // a plain GET included: the data can leave in the URL.
    let network = (session_sensitive || sensitive)
        && network_call(&analysis.actions, &rules.network_commands);
    Flags {
        untrusted: rules.untrusted_bash.iter().any(|re| re.is_match(&actions))
            || reads_foreign(&analysis.actions, foreign, cwd),
        sensitive,
        external: network || rules.external.iter().any(|re| re.is_match(&actions)),
        written,
        foreign: foreign_new,
        ..Flags::default()
    }
}

/// True when a command runs a network tool (the first word of an exec line).
fn network_call(actions: &[String], commands: &[String]) -> bool {
    actions.iter().any(|line| {
        line.strip_prefix("exec ")
            .and_then(|words| words.split_whitespace().next())
            .map(|first| first.rsplit('/').next().unwrap_or(""))
            .is_some_and(|name| commands.iter().any(|c| c == name))
    })
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
    let added = classify_with(event, rules, &before);
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
    store.update(session, |mut flags| {
        if !flags.frozen {
            return Ok((flags, None));
        }
        let freeze = flags.freeze.take().unwrap_or_default();
        flags.frozen = false;
        flags.untrusted = false;
        flags.sensitive = false;
        flags.external = false;
        let released = Released {
            trigger: freeze.trigger,
            case: freeze.case,
            blocked: freeze.blocked,
            by: by.to_string(),
            at: at.to_string(),
        };
        Ok((flags, Some(released)))
    })
}

/// Session state in one SQLite file (`~/.agentcop/state.db`): one row per session, holding its JSON state.
/// `update` reads, decides and writes in one IMMEDIATE transaction, so parallel hook processes
/// cannot lose each other's updates (2026-10-27: the old one-file-per-session JSON could).
/// One human decision, as stored in the `decisions` table.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DecisionRow {
    pub seq: i64,
    pub case_id: String,
    pub action: String,
    pub at: String,
    pub prev: String,
    pub hash: String,
}

pub struct SessionStore {
    path: PathBuf,
}

impl SessionStore {
    /// Open the state file, creating its table if needed.
    pub fn open(path: &Path) -> Result<Self, String> {
        let store = SessionStore {
            path: path.to_path_buf(),
        };
        store.connect()?;
        cop_core::perms::secure_file(path)?;
        Ok(store)
    }

    fn connect(&self) -> Result<Connection, String> {
        let conn = Connection::open(&self.path).map_err(|e| format!("open session state: {e}"))?;
        conn.busy_timeout(Duration::from_secs(10))
            .map_err(|e| format!("open session state: {e}"))?;
        conn.execute(
            "CREATE TABLE IF NOT EXISTS sessions (key TEXT PRIMARY KEY, state TEXT NOT NULL)",
            [],
        )
        .map_err(|e| format!("open session state: {e}"))?;
        // Human decisions (release, convict), one hash-chained row each (2026-10-27: moved from decisions.jsonl).
        conn.execute(
            "CREATE TABLE IF NOT EXISTS decisions (
                seq INTEGER PRIMARY KEY,
                case_id TEXT NOT NULL,
                action TEXT NOT NULL,
                at TEXT NOT NULL,
                prev TEXT NOT NULL,
                hash TEXT NOT NULL
            )",
            [],
        )
        .map_err(|e| format!("open session state: {e}"))?;
        Ok(conn)
    }

    pub fn load(&self, session_id: Option<&str>) -> Result<Flags, String> {
        let conn = self.connect()?;
        read_state(&conn, session_key(session_id))
    }

    /// Import a session row from a legacy JSON file. The key is recorded as `legacy:<digest>`: the file name
    /// is a hash of the session id, so the live session id can not be recovered and the row never matches a
    /// live session. It stays for audit. Existing rows are kept.
    pub fn import_legacy_session(&self, digest: &str, state_json: &str) -> Result<(), String> {
        let conn = self.connect()?;
        conn.execute(
            "INSERT OR IGNORE INTO sessions (key, state) VALUES (?1, ?2)",
            [format!("legacy:{digest}"), state_json.to_string()],
        )
        .map_err(|e| format!("import session: {e}"))?;
        Ok(())
    }

    /// Number of rows in the decisions table (for migration checks and tests).
    pub fn decision_count(&self) -> Result<u64, String> {
        let conn = self.connect()?;
        conn.query_row("SELECT COUNT(*) FROM decisions", [], |row| {
            row.get::<_, i64>(0)
        })
        .map(|n| n as u64)
        .map_err(|e| format!("count decisions: {e}"))
    }

    /// Number of imported legacy session rows.
    pub fn legacy_session_count(&self) -> Result<u64, String> {
        let conn = self.connect()?;
        conn.query_row(
            "SELECT COUNT(*) FROM sessions WHERE key LIKE 'legacy:%'",
            [],
            |row| row.get::<_, i64>(0),
        )
        .map(|n| n as u64)
        .map_err(|e| format!("count sessions: {e}"))
    }

    /// Import one decision from the legacy decisions.jsonl. Existing sequence numbers are kept.
    pub fn import_decision(&self, d: &DecisionRow) -> Result<(), String> {
        let conn = self.connect()?;
        conn.execute(
            "INSERT OR IGNORE INTO decisions (seq, case_id, action, at, prev, hash) VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
            rusqlite::params![d.seq, d.case_id, d.action, d.at, d.prev, d.hash],
        )
        .map_err(|e| format!("import decision: {e}"))?;
        Ok(())
    }

    pub fn save(&self, session_id: Option<&str>, flags: Flags) -> Result<(), String> {
        let conn = self.connect()?;
        write_state(&conn, session_key(session_id), &flags)
    }

    /// Read the session, decide, and write the result back, in one transaction. If `decide` fails,
    /// nothing is written (fail closed).
    pub fn update<T>(
        &self,
        session_id: Option<&str>,
        decide: impl FnOnce(Flags) -> Result<(Flags, T), String>,
    ) -> Result<T, String> {
        let mut conn = self.connect()?;
        let key = session_key(session_id);
        let tx = conn
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(|e| format!("session transaction: {e}"))?;
        let before = read_state(&tx, key)?;
        let (after, out) = decide(before)?;
        write_state(&tx, key, &after)?;
        tx.commit().map_err(|e| format!("session commit: {e}"))?;
        Ok(out)
    }
}

fn session_key(session_id: Option<&str>) -> &str {
    session_id.unwrap_or("unknown")
}

fn read_state(conn: &Connection, key: &str) -> Result<Flags, String> {
    match conn.query_row("SELECT state FROM sessions WHERE key = ?1", [key], |row| {
        row.get::<_, String>(0)
    }) {
        Ok(text) => {
            serde_json::from_str(&text).map_err(|e| format!("session state is corrupt: {e}"))
        }
        Err(rusqlite::Error::QueryReturnedNoRows) => Ok(Flags::default()),
        Err(e) => Err(format!("read session state: {e}")),
    }
}

fn write_state(conn: &Connection, key: &str, flags: &Flags) -> Result<(), String> {
    let text = serde_json::to_string(flags).map_err(|e| e.to_string())?;
    conn.execute(
        "INSERT INTO sessions (key, state) VALUES (?1, ?2)
         ON CONFLICT(key) DO UPDATE SET state = excluded.state",
        [key, text.as_str()],
    )
    .map_err(|e| format!("write session state: {e}"))?;
    Ok(())
}
