//! Shell-aware normalizer (C2-R): turn a Bash command into the actions it would really take.
//!
//! PLAN:
//! 1. Parse the command with tree-sitter-bash (a full Bash grammar; error-tolerant, so we can detect bad input).
//! 2. Walk the tree. Every executed simple command becomes an `exec` line, with quotes removed (`r''m` is `rm`).
//! 3. A redirect to a real file, or a file argument of a write command, becomes a `write` line.
//!    `/dev/*` and fd duplicates (`2>&1`) are not writes.
//! 4. A pipeline of two or more commands becomes a `pipe` line.
//! 5. Heredoc bodies and quoted text are data: never walked as commands.
//! 6. `bash -c`, `sh -c` and `eval` strings are parsed again as commands (depth-limited).
//! 7. A parse error or too-deep nesting sets `unparsed`. The judge denies on that (fail closed).

mod secret;

pub use secret::{file_operands, is_secret_path, is_secret_with};

use tree_sitter::{Node, Parser};

/// How deep `bash -c` nesting may go before we give up (fail closed).
const MAX_DEPTH: usize = 4;

/// What a Bash command would do, as plain action lines the policy and taint rules match.
#[derive(Debug, Default, PartialEq, Eq)]
pub struct Analysis {
    pub actions: Vec<String>,
    /// The 1-based script line each action came from, parallel to `actions`.
    pub lines: Vec<usize>,
    pub unparsed: bool,
}

/// Analyze one Bash command string.
pub fn analyze(command: &str) -> Analysis {
    let mut out = Analysis::default();
    analyze_into(command, 0, 0, &mut out);
    out
}

fn analyze_into(src: &str, depth: usize, base_line: usize, out: &mut Analysis) {
    if depth > MAX_DEPTH {
        out.unparsed = true;
        return;
    }
    let mut parser = Parser::new();
    if parser
        .set_language(&tree_sitter_bash::LANGUAGE.into())
        .is_err()
    {
        out.unparsed = true;
        return;
    }
    let Some(tree) = parser.parse(src, None) else {
        out.unparsed = true;
        return;
    };
    let root = tree.root_node();
    if root.has_error() {
        out.unparsed = true;
    }
    let mut walker = Walker {
        src: src.as_bytes(),
        depth,
        base_line,
        cur: base_line + 1,
        out,
        cwd: None,
        cwd_unknown: false,
    };
    walker.visit(root);
}

struct Walker<'a> {
    src: &'a [u8],
    depth: usize,
    /// Line offset of this text inside the outer script (0 at the top).
    base_line: usize,
    /// Script line of the node being visited; every action takes it.
    cur: usize,
    out: &'a mut Analysis,
    /// Directory set by a literal `cd` earlier in the same command, for relative write paths.
    cwd: Option<String>,
    /// A `cd` to a run-time value made the directory unknown: relative paths can not be resolved.
    cwd_unknown: bool,
}

impl Walker<'_> {
    fn visit(&mut self, node: Node) {
        self.cur = self.base_line + node.start_position().row + 1;
        match node.kind() {
            "heredoc_body" => {}
            "redirected_statement" => {
                // The redirect sits on this node; the command it wraps is the body.
                self.redirect_targets(node);
                let mut cursor = node.walk();
                let kids: Vec<Node> = node.children(&mut cursor).collect();
                for kid in kids {
                    self.visit(kid);
                }
            }
            "command" => self.command(node),
            "pipeline" => self.pipeline(node),
            _ => {
                let mut cursor = node.walk();
                let kids: Vec<Node> = node.children(&mut cursor).collect();
                for kid in kids {
                    self.visit(kid);
                }
            }
        }
    }

    /// Record one action with the line it came from.
    fn emit(&mut self, text: String) {
        self.out.actions.push(text);
        self.out.lines.push(self.cur);
    }

    fn text(&self, node: Node) -> String {
        node.utf8_text(self.src).unwrap_or("").to_string()
    }

    /// Quote removal, the way bash reads a word: `r''m` is `rm`, `'a\b'` keeps the backslash.
    fn word(&self, node: Node) -> String {
        unquote(&self.text(node))
    }

    /// The argv of a `command` node: command name first, then arguments.
    /// Redirects, comments and `VAR=value` prefixes are not words.
    fn argv(&self, node: Node) -> Vec<String> {
        let mut cursor = node.walk();
        node.named_children(&mut cursor)
            .filter(|k| !is_skipped(k.kind()))
            .map(|k| self.word(k))
            .collect()
    }

    /// Record that we cannot tell statically what runs. The judge asks (never allows).
    fn uncertain(&mut self, reason: &str) {
        self.emit(format!("uncertain {reason}"));
    }

    /// Look at the command word and its arguments: dynamic names, decoded payloads, inline code.
    fn judge_name(&mut self, node: Node, argv: &[String]) {
        if self.name_is_dynamic(node) {
            self.uncertain("the command name is built at run time");
        }
        let name = base_name(&argv[0]);
        if is_decoder(&name, &argv[1..]) {
            self.uncertain("a decoded payload may run");
        }
        if runs_code(&name) {
            // Code given inline (python -c, sqlite3 ...) is judged as text: it may name protected state.
            self.emit(format!("inline {}", argv.join(" ")));
        }
    }

    /// True when the command word contains `$` or a backtick, so its name is not fixed text.
    fn name_is_dynamic(&self, node: Node) -> bool {
        let mut cursor = node.walk();
        let first = node
            .named_children(&mut cursor)
            .find(|k| !is_skipped(k.kind()));
        first.is_some_and(|k| {
            let text = self.text(k);
            text.contains('$') || text.contains('`')
        })
    }

    fn command(&mut self, node: Node) {
        let argv = self.argv(node);
        if !argv.is_empty() {
            self.emit(format!("exec {}", argv.join(" ")));
            for operand in secret::command_operands(&argv) {
                self.emit(format!("operand {operand}"));
            }
            self.judge_name(node, &argv);
            self.script_target(&argv);
            self.runner_target(&argv);
            self.find_delete_target(&argv);
            self.destructive_target(&argv);
            self.network_target(&argv);
            self.track_cd(&argv);
            self.write_targets(&argv);
            self.wrapped_command(&argv);
        }
        // A bare `> file` has no words but still writes.
        self.redirect_targets(node);
        // Command substitutions and subshells inside the words are commands too.
        let mut cursor = node.walk();
        let kids: Vec<Node> = node.named_children(&mut cursor).collect();
        for kid in kids {
            if is_redirect(kid.kind()) {
                continue;
            }
            self.visit(kid);
        }
    }

    fn pipeline(&mut self, node: Node) {
        let mut cursor = node.walk();
        let stages: Vec<Node> = node
            .named_children(&mut cursor)
            .filter(|k| k.kind() == "command")
            .collect();
        if stages.len() >= 2 {
            let argvs: Vec<Vec<String>> = stages.iter().map(|s| self.argv(*s)).collect();
            let parts: Vec<String> = argvs.iter().map(|a| a.join(" ")).collect();
            self.emit(format!("pipe {}", parts.join(" | ")));
            // Text piped into a shell or interpreter runs as code we cannot read here.
            for argv in argvs.iter().skip(1).filter(|a| !a.is_empty()) {
                if runs_code(&base_name(&argv[0])) {
                    self.uncertain("text is piped into a shell or interpreter");
                }
            }
        }
        let mut cursor = node.walk();
        let kids: Vec<Node> = node.children(&mut cursor).collect();
        for kid in kids {
            self.visit(kid);
        }
    }

    /// A command that runs a script file: `bash x.sh`, `sh x`, `source x`, `. x`, or a path like `./x.sh`.
    /// `script` means the file must be a script (missing or unreadable asks). `script-maybe` is a path
    /// that may be a binary; the judge reads only its first bytes and skips it unless it starts with `#!`.
    fn script_target(&mut self, argv: &[String]) {
        let name = base_name(&argv[0]);
        let shell_args = &argv[1..];
        let target: Option<(String, bool)> = if SHELLS.contains(&name.as_str()) {
            let runs_string = shell_args
                .iter()
                .any(|a| a.starts_with('-') && !a.starts_with("--") && a.contains('c'));
            if runs_string {
                None
            } else {
                shell_args
                    .iter()
                    .find(|a| !a.starts_with('-'))
                    .map(|a| (a.clone(), false))
            }
        } else if name == "source" || name == "." {
            argv.get(1).map(|a| (a.clone(), false))
        } else if argv[0].contains('/') {
            let is_script = [".sh", ".bash", ".zsh"]
                .iter()
                .any(|ext| argv[0].ends_with(ext));
            Some((argv[0].clone(), !is_script))
        } else {
            None
        };
        if let Some((path, maybe)) = target {
            let kind = if maybe { "script-maybe" } else { "script" };
            if self.relative_unknown(&path) {
                self.uncertain("the directory of a script is set at run time");
                return;
            }
            let resolved = self.normalize(&path);
            self.emit(format!("{kind} {resolved}"));
        }
    }

    /// A network tool whose arguments (the URL, the host) are built at run time: the request can not be read, so ask.
    fn network_target(&mut self, argv: &[String]) {
        let name = base_name(&argv[0]);
        let built = argv[1..].iter().any(|a| a.contains(['$', '`']));
        if NETWORK_TOOLS.contains(&name.as_str()) && built {
            self.uncertain("a network request is built at run time");
        }
    }

    /// Delete, format or re-own commands whose target we cannot read: they ask.
    fn destructive_target(&mut self, argv: &[String]) {
        if destructive_with_unknown_target(argv) {
            self.uncertain("a destructive command has a variable or glob target");
        }
    }

    /// Files that a runner executes (python, node, ruby, perl, php, lua, make, npm run, npx, cargo).
    /// The judge asks when one of them was written this session.
    fn runner_target(&mut self, argv: &[String]) {
        let name = base_name(&argv[0]);
        let args = &argv[1..];
        let interpreter = name.starts_with("python")
            || matches!(name.as_str(), "perl" | "node" | "ruby" | "php" | "lua");
        let files: Vec<String> = if interpreter {
            let inline = args
                .iter()
                .any(|a| matches!(a.as_str(), "-c" | "-e" | "-E" | "-m" | "-p"));
            let first = args.iter().find(|a| !a.starts_with('-'));
            if inline {
                Vec::new()
            } else {
                first.cloned().into_iter().collect()
            }
        } else if name == "make" {
            match args.iter().position(|a| a == "-f") {
                Some(i) => args.get(i + 1).cloned().into_iter().collect(),
                None => vec!["Makefile".to_string()],
            }
        } else if name == "npm"
            && args.first().is_some_and(|s| {
                matches!(s.as_str(), "run" | "run-script" | "test" | "start" | "exec")
            })
        {
            vec!["package.json".to_string()]
        } else if name == "npx" {
            args.iter()
                .find(|a| !a.starts_with('-'))
                .cloned()
                .into_iter()
                .collect()
        } else if name == "cargo"
            && args
                .first()
                .is_some_and(|s| matches!(s.as_str(), "run" | "build" | "test" | "check" | "bench"))
        {
            vec!["build.rs".to_string()]
        } else {
            Vec::new()
        };
        for file in files {
            if self.relative_unknown(&file) {
                self.uncertain("the directory of a file that runs is set at run time");
            } else {
                let resolved = self.normalize(&file);
                self.emit(format!("runs-file {resolved}"));
            }
        }
    }

    /// `find ... -delete`: the start paths are the words before the first expression. A quoted
    /// pattern (`'*.log'`) is a find pattern, not a shell glob, so it is not a target.
    fn find_delete_target(&mut self, argv: &[String]) {
        if base_name(&argv[0]) != "find" || !argv.iter().any(|a| a == "-delete") {
            return;
        }
        let starts: Vec<String> = argv[1..]
            .iter()
            .take_while(|a| !(a.starts_with('-') || a.starts_with('(') || a.starts_with('!')))
            .cloned()
            .collect();
        let starts = if starts.is_empty() {
            vec![".".to_string()]
        } else {
            starts
        };
        for start in starts {
            if start.contains(['$', '`']) {
                self.uncertain("the find start path is set at run time");
            } else if self.relative_unknown(&start) {
                self.uncertain("the directory of a find start path is set at run time");
            } else {
                let resolved = self.normalize(&start);
                self.emit(format!("find-delete {resolved}"));
            }
        }
    }

    /// `cd` with a literal target sets the directory for later relative paths. A run-time target
    /// (a variable or a backtick) makes the directory unknown until an absolute `cd`.
    fn track_cd(&mut self, argv: &[String]) {
        if argv[0] != "cd" {
            return;
        }
        match argv.get(1) {
            None => {
                self.cwd = Some("~".to_string());
                self.cwd_unknown = false;
            }
            Some(dir) if run_time_word(dir) => {
                self.cwd = None;
                self.cwd_unknown = true;
                self.uncertain("the directory is set at run time");
            }
            Some(dir) => {
                if self.cwd_unknown && !is_absolute_word(dir) {
                    return;
                }
                self.cwd_unknown = false;
                self.cwd = Some(self.normalize(dir));
            }
        }
    }

    /// A relative path while the directory is unknown can not be resolved, so the judge must ask.
    fn relative_unknown(&self, path: &str) -> bool {
        self.cwd_unknown && !is_absolute_word(path)
    }

    /// File arguments of commands that write files. Only the words that name files count.
    fn write_targets(&mut self, argv: &[String]) {
        let name = argv[0].rsplit('/').next().unwrap_or("");
        let args = &argv[1..];
        match name {
            "rm" | "mv" | "cp" | "tee" | "ln" | "touch" | "truncate" | "shred" | "chmod"
            | "chown" => {
                for a in args.iter().filter(|a| !a.starts_with('-')) {
                    self.write(a);
                }
            }
            "sed" if args.iter().any(|a| a == "-i" || a.starts_with("-i")) => {
                // The first non-option word is the script; the rest are files.
                for a in args.iter().filter(|a| !a.starts_with('-')).skip(1) {
                    self.write(a);
                }
            }
            "dd" => {
                for a in args.iter().filter_map(|a| a.strip_prefix("of=")) {
                    self.write(a);
                }
            }
            _ => {}
        }
    }

    /// Output redirects to real files. `<` is a read. `2>&1`, `>&-` and `>/dev/null` are not writes.
    fn redirect_targets(&mut self, node: Node) {
        let mut cursor = node.walk();
        let redirects: Vec<Node> = node
            .named_children(&mut cursor)
            .filter(|k| k.kind() == "file_redirect")
            .collect();
        for r in redirects {
            let text = self.text(r);
            if !text.contains('>') {
                continue;
            }
            let target = self.word_text_of_dest(r);
            if target.starts_with("/dev/") {
                continue;
            }
            let is_fd_dup =
                text.contains(">&") && target.chars().all(|c| c.is_ascii_digit() || c == '-');
            if !is_fd_dup {
                self.write(&target);
            }
        }
    }

    /// The destination word of a file redirect, quote-free.
    fn word_text_of_dest(&self, redirect: Node) -> String {
        let mut cursor = redirect.walk();
        redirect
            .named_children(&mut cursor)
            .last()
            .map(|n| self.word(n))
            .unwrap_or_default()
    }

    /// `bash -c "..."`, `sh -c "..."` and `eval ...`: parse the string as its own command line.
    fn wrapped_command(&mut self, argv: &[String]) {
        let name = argv[0].rsplit('/').next().unwrap_or("");
        let inner: Option<String> = match name {
            "bash" | "sh" | "zsh" | "dash" | "ksh" => argv
                .iter()
                .position(|a| a.starts_with('-') && !a.starts_with("--") && a.contains('c'))
                .and_then(|i| argv.get(i + 1))
                .cloned(),
            "eval" if argv.len() > 1 => Some(argv[1..].join(" ")),
            _ => None,
        };
        if let Some(code) = inner {
            analyze_into(&code, self.depth + 1, self.cur.saturating_sub(1), self.out);
        }
    }

    /// `$HOME/x` and `${HOME}/x` become `~/x`. A relative path is joined to the last literal `cd`.
    fn normalize(&self, path: &str) -> String {
        let home_fixed = path
            .strip_prefix("$HOME/")
            .or_else(|| path.strip_prefix("${HOME}/"))
            .map(|rest| format!("~/{rest}"))
            .unwrap_or_else(|| path.to_string());
        let is_absolute = home_fixed.starts_with('/') || home_fixed.starts_with('~');
        match (&self.cwd, is_absolute) {
            (Some(dir), false) => format!("{dir}/{home_fixed}"),
            _ => home_fixed,
        }
    }

    fn write(&mut self, path: &str) {
        if path.starts_with("/dev/") || path.is_empty() {
            return;
        }
        if self.relative_unknown(path) {
            self.uncertain("the directory of a file that is written is set at run time");
            return;
        }
        let normalized = self.normalize(path);
        self.emit(format!("write {normalized}"));
    }
}

fn is_redirect(kind: &str) -> bool {
    matches!(
        kind,
        "file_redirect" | "heredoc_redirect" | "herestring_redirect"
    )
}

/// Child nodes of a `command` that are not words of the argv.
fn is_skipped(kind: &str) -> bool {
    is_redirect(kind) || kind == "comment" || kind == "variable_assignment"
}

/// Tools that send or fetch over the network.
const NETWORK_TOOLS: [&str; 13] = [
    "curl", "wget", "nc", "ncat", "ssh", "scp", "sftp", "rsync", "ftp", "dig", "nslookup", "host",
    "telnet",
];

/// Shells that run a script file when given one.
const SHELLS: [&str; 5] = ["sh", "bash", "zsh", "dash", "ksh"];

/// Commands that delete, format or re-own files, with a target that is a variable or a glob.
fn destructive_with_unknown_target(argv: &[String]) -> bool {
    let name = base_name(&argv[0]);
    let args = &argv[1..];
    let short = |a: &String, letters: &str| {
        a.starts_with('-') && !a.starts_with("--") && letters.chars().any(|c| a.contains(c))
    };
    let destructive = match name.as_str() {
        "rm" => args
            .iter()
            .any(|a| short(a, "rRf") || a == "--recursive" || a == "--force"),
        "dd" => true,
        n if n.starts_with("mkfs") => true,
        "chmod" | "chown" => args.iter().any(|a| short(a, "R") || a == "--recursive"),
        "git" => {
            args.first().is_some_and(|sub| sub == "clean") && args.iter().any(|a| short(a, "f"))
        }
        _ => false,
    };
    let unknown_target = args.iter().any(|a| a.contains(['$', '`', '*', '?', '[']));
    destructive && unknown_target
}

/// A word whose value is only known at run time: it has `$` or a backtick, other than `$HOME/`.
fn run_time_word(word: &str) -> bool {
    let rest = word
        .strip_prefix("$HOME/")
        .or_else(|| word.strip_prefix("${HOME}/"))
        .unwrap_or(word);
    rest.contains(['$', '`'])
}

/// A path that does not depend on the current directory.
fn is_absolute_word(word: &str) -> bool {
    word.starts_with('/')
        || word.starts_with('~')
        || word.starts_with("$HOME/")
        || word.starts_with("${HOME}/")
}

fn base_name(word: &str) -> String {
    word.rsplit('/').next().unwrap_or("").to_string()
}

/// Shells and interpreters: text given to them runs as code.
fn runs_code(name: &str) -> bool {
    matches!(
        name,
        "sh" | "bash"
            | "zsh"
            | "dash"
            | "ksh"
            | "perl"
            | "node"
            | "ruby"
            | "php"
            | "lua"
            | "sqlite3"
    ) || name.starts_with("python")
}

/// Tools that turn encoded text back into bytes: base64 -d, openssl base64 -d, xxd -r.
fn is_decoder(name: &str, args: &[String]) -> bool {
    let short_flag =
        |a: &String, letter: char| a.starts_with('-') && !a.starts_with("--") && a.contains(letter);
    match name {
        "base64" => args
            .iter()
            .any(|a| a == "--decode" || short_flag(a, 'd') || short_flag(a, 'D')),
        "openssl" => {
            args.iter().any(|a| a == "base64") && args.iter().any(|a| a == "-d" || a == "-decode")
        }
        "xxd" => args.iter().any(|a| a.starts_with("-r")),
        _ => false,
    }
}

#[derive(Clone, Copy, PartialEq)]
enum Quote {
    Plain,
    Single,
    Double,
}

/// Remove shell quoting from one word. Inside single quotes nothing is special.
/// Inside double quotes a backslash only escapes `$`, backtick, `"`, `\` and newline.
fn unquote(raw: &str) -> String {
    let mut out = String::new();
    let mut state = Quote::Plain;
    let mut chars = raw.chars().peekable();
    while let Some(c) = chars.next() {
        state = match (state, c) {
            (Quote::Plain, '\\') => {
                if let Some(next) = chars.next() {
                    out.push(next);
                }
                Quote::Plain
            }
            (Quote::Plain, '\'') => Quote::Single,
            (Quote::Plain, '"') => Quote::Double,
            (Quote::Single, '\'') => Quote::Plain,
            (Quote::Single, _) => {
                out.push(c);
                Quote::Single
            }
            (Quote::Double, '"') => Quote::Plain,
            (Quote::Double, '\\') => {
                match chars.peek() {
                    Some(&n) if "$`\"\\\n".contains(n) => {
                        out.push(n);
                        chars.next();
                    }
                    _ => out.push('\\'),
                }
                Quote::Double
            }
            (state, _) => {
                out.push(c);
                state
            }
        };
    }
    out
}
