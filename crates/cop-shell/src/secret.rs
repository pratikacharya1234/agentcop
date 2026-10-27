//! Secret files by name (FP-1, 2026-10-26). PLAN:
//! 1. `is_secret_path` takes one path word. It is secret by its file NAME: `.env` or `.env.<anything>`, `.netrc`,
//!    `id_rsa*`, `id_ed25519*`, `*.pem`, `/etc/shadow`, anything under a `.ssh` folder, `.aws/credentials`, and
//!    `hmac.key` in `.agentcop`. Other `.agentcop` files (evidence, state, policy) are not secret.
//! 2. `file_operands` takes the action lines of a parsed command and returns the words that name files: the
//!    arguments of commands, and the targets of writes. A search pattern (the first operand of grep, sed, awk
//!    and similar) is not a file, and echo or printf text is not a file either.
//! 3. Nothing here matches regexes over raw text, so text inside a pattern or a quoted string cannot trigger it.
//!
//! Edge cases: `-e` or `-f` give grep its pattern, so no operand is skipped. A flag word (starts with `-`) is never a file.

/// Commands whose first operand is a search or edit script, not a file.
const PATTERN_FIRST: [&str; 7] = ["grep", "egrep", "fgrep", "rg", "ag", "ack", "sed"];

/// Commands whose arguments are text, never files.
const TEXT_ONLY: [&str; 3] = ["echo", "printf", "awk"];

/// True when this path word names a secret file, judged by its name.
pub fn is_secret_path(word: &str) -> bool {
    let name = word.rsplit('/').next().unwrap_or(word);
    if name == ".env" || name.starts_with(".env.") {
        return true;
    }
    if name.starts_with("id_rsa") || name.starts_with("id_ed25519") || name == ".netrc" {
        return true;
    }
    if name.ends_with(".pem") || word == "/etc/shadow" {
        return true;
    }
    let parts: Vec<&str> = word.split('/').collect();
    if parts.contains(&".ssh") {
        return true;
    }
    if parts.windows(2).any(|pair| pair == [".aws", "credentials"]) {
        return true;
    }
    name == "hmac.key" && parts.contains(&".agentcop")
}

/// The file operands of a parsed command: one word per operand, from the `operand` action lines, plus the
/// targets of writes.
pub fn file_operands(actions: &[String]) -> Vec<String> {
    actions
        .iter()
        .filter_map(|line| {
            line.strip_prefix("operand ")
                .or_else(|| line.strip_prefix("write "))
                .map(str::to_string)
        })
        .collect()
}

/// The file operands of one command, from its argument list (quotes already removed, so a quoted pattern with
/// spaces is one word). The first word is the command name.
pub(crate) fn command_operands(argv: &[String]) -> Vec<String> {
    let Some((name, args)) = argv.split_first() else {
        return Vec::new();
    };
    let name = name.rsplit('/').next().unwrap_or(name);
    if TEXT_ONLY.contains(&name) {
        return Vec::new();
    }
    let mut operands: Vec<String> = args
        .iter()
        .filter(|w| !w.starts_with('-'))
        .cloned()
        .collect();
    let gives_pattern = args.iter().any(|w| w == "-e" || w == "-f");
    if PATTERN_FIRST.contains(&name) && !gives_pattern && !operands.is_empty() {
        operands.remove(0);
    }
    // `@file` names a file whose contents are sent (curl -d @file, -F name=@file). Added after the pattern is
    // dropped, so a pattern that contains `@` is not read as a file.
    let at_files: Vec<String> = operands
        .iter()
        .filter_map(|w| w.split_once('@').map(|(_, file)| file.to_string()))
        .collect();
    operands.extend(at_files);
    operands
}
