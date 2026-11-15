# Changelog

## v0.1.0-beta (unreleased)

### Added
- A published list of every known bypass in this release: "Known bypasses (v0.1.0-beta)" in [WHAT-AGENTCOP-DOES-NOT-CATCH.md](WHAT-AGENTCOP-DOES-NOT-CATCH.md).
- A beta banner in the README (do not run in production; log-only by default) and a roadmap for v0.1.1 and v0.2.

### Changed
- Documentation only: the README no longer promises audio, terminal theatrics, or adapters for other agents, because those are not in this build.

## Unreleased (v0.1 candidate)

### Added
- Hook (`cop-hook`) for Claude Code `PreToolUse`: judges every tool call, records it, and fails closed (deny) on any error.
- Judge rules in `policy/default.toml`: destructive removes, production deletes, secret-file reads, pipe-to-shell, stopping or editing the cop, `git push` asks.
- Hash-chained SQLite evidence store and `agentcop verify`.
- `agentcop install` / `uninstall`: backs up `settings.json`, writes the hook with `onFailure: block`, copies the default policy, supports `--dry-run`.
- `agentcop cases` (with case IDs and reasons) and `agentcop fix CASE-<id>` (deny-only suggestion, asks before writing, validates, keeps a backup).
- Every verdict names its case: `[CASE-xxxxxxxxxxxx]`.
- Log-only mode: `mode = "log-only"` in the policy records what would be blocked and allows the call.
- Rule of Two (`cop-taint`): sessions with untrusted input, sensitive data and an external action are frozen.
- Egress proxy (`cop-proxy`): host allowlist for CONNECT, secret scan on plaintext HTTP URLs and bodies.
- Holding cell library (`cop-cell`): cgroup v2 freeze with SIGSTOP fallback, snapshot, thaw, kill.
- Case bundle (`cop-bundle`) with a JSON schema: agent text is quoted and size-capped.
- Python detective (`detective/`): raise-only severity, strict output schema, no tools, offline template provider.
- Courtroom (`courtroom/`): local dashboard on 127.0.0.1 with a random token: timeline, mugshot card and PNG (redacted), Release and Convict decisions in a hash-chained file, blotter, Wanted list, ranks, synthesized sound with mute.
- Attack suite (`tests/attacks/`): 36 hook and detective cases, run by `scripts/check.sh`.
- Sound pack validator and a default pack (`courtroom/sound-packs/default`).

### Changed
- Cop-protection rules deny writes only. Reads of cop state and settings are allowed.

### Known limits
See [WHAT-AGENTCOP-DOES-NOT-CATCH.md](WHAT-AGENTCOP-DOES-NOT-CATCH.md). The command-line hook has no audio and no terminal theatrics in this build; the sound engine is a stub and the fun layer is planned for v0.2. Only Claude Code is supported.
