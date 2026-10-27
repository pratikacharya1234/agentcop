# What AgentCop does not catch

DRAFT for owner review. Not published. This page lists what AgentCop misses today, so nobody reads more into a passing check than is there. Known misses are also tracked in the attack suite ([docs/internal-affairs.md](internal-affairs.md)) and in [THREAT_MODEL.md](../THREAT_MODEL.md).

## Coverage limits
- **Claude Code only.** `agentcop install` writes the hook to `~/.claude/settings.json`. Nothing installs into Codex, OpenCode, or other agents, even though a Codex parser exists as library code.
- **Linux first, and only on Linux tested.** macOS and Windows are untested.
- **No live kernel monitoring.** The eBPF/syscall sensors (`cop-ebpf`, `cop-family`, `cop-syscalls`) are library code tested with fixtures. Nothing loads a kernel probe.
- **The holding cell is not connected.** `cop-cell` can freeze processes, but no running component calls it. A Rule of Two freeze blocks tool calls only.

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
