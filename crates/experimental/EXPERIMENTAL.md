# Experimental crates

These crates are **not part of AgentCop**. They are not built by `./scripts/check.sh`, they are not
shipped, and nothing in the released binaries depends on them. They moved here on 2026-11-15
(v0.1.0-beta release prep) because they were dead weight inside the workspace: `cargo test --all`
was counting 122 tests that no live code path could ever reach, which made the green check look
bigger than the product actually was.

The live product is eight crates:

```
cop-hook   cop-cli   cop-core   cop-policy   cop-evidence   cop-shell   cop-taint   cop-siren
```

Everything below this line is library code and experiments. Each crate here is a **standalone
package**: it has its own `[workspace]` table, so it can be built and tested on its own without
touching the AgentCop workspace.

## How to work with one of these

```bash
cd crates/experimental/cop-proxy
cargo test          # builds and tests only this crate
```

They are excluded from the root `Cargo.toml` (`exclude = [...]`), so `cargo build --workspace` and
`cargo test --workspace` at the repo root ignore them. Their own `Cargo.lock` files are generated
on first build and are not tracked.

## What each one is

| Crate | What it is | State | Plan |
| --- | --- | --- | --- |
| `cop-bundle` | Builds the case bundle JSON (agent text quoted and size-capped) that the Python detective reads. | **library-only, no producer.** Nothing in the product emits a bundle, so the "case → bundle → detective" chain does not exist. Has a JSON schema (`schemas/case-bundle.schema.json`) and 13 tests. | v0.2: wire a CLI command to it, or delete it. |
| `cop-cell` | Holding cell: cgroup v2 freeze (`cgroup.freeze`), `SIGSTOP` fallback, snapshot, thaw, kill. | **library-only, correct but unreachable.** No running component calls `freeze`. The one real-hardware test skips unless `AGENTCOP_CELL_CGROUP_ROOT` is set. | v0.2: wire into the verdict path (see `.github/issues-v0.2/holding-cell-wired.md`), or delete it. |
| `cop-codex` | LLM prompt builder for verdict explanations, with a mock response. | **stub / wrong component.** It is not a Codex hook adapter: there is no `~/.codex/hooks.json` handling and no `agentcop install --codex`. It also puts an LLM on the path, which the project rules forbid. | v0.2: replace with a real Codex adapter (`.github/issues-v0.2/codex-adapter.md`), or delete it. |
| `cop-ebpf` | Process-execution monitor and evasion scorer. | **library-only.** No `aya` dependency, no kernel program, no BPF object. Regexes are recompiled per event. | v0.2: implement the real eBPF sensor with `aya` (`.github/issues-v0.2/os-sensors-live.md`), or delete it. |
| `cop-family` | Maps a pid/ppid tree to a session and scores privilege escalation and shell chains. | **library-only.** Never linked to a real session id. Depends on `cop-ebpf`. | v0.2 with the eBPF sensor, or delete it. |
| `cop-syscalls` | File-open and outbound-connect observation with a suspicious path/port list. | **library-only.** No tracer. Depends on `cop-ebpf`. | v0.2 with the eBPF sensor, or delete it. |
| `cop-honeypot` | Traps for fake credentials, canary hosts and decoy files. | **library-only, not wired.** The shipped honeytokens live in `policy/default.toml` and are read by `cop-policy`; this crate is not on the enforcement path. There is no `agentcop plant` command. | v0.2: implement `agentcop plant` on top of it, or delete it. |
| `cop-logger` | Verdict-log formatter and a token-bucket rate limiter. | **library-only.** `Logger::log()` returns a string and writes nothing to disk. This is what the old "C1 daemon" commit actually built; there is no daemon and no socket anywhere in the project. | Delete, or rebuild as a real daemon. |
| `cop-normalizer` | Parses hook / eBPF / proxy JSON into an `AgentEvent`. | **superseded.** `cop-shell` (tree-sitter-bash) is the real normalizer. This crate still reads the pre-fix `hook_type` key, so it would mis-parse real Claude Code input. | Delete. |
| `cop-pipeline` | An eight-step orchestrator (normalize → honeypot → rate limit → judge → evidence → log). | **library-only.** Nothing depends on it. It also swallows evidence-write errors (`let _ = store.append(...)`), which is fail-open in a fail-closed project. | Delete, or rebuild as the real pipeline. |
| `cop-proxy` | Egress proxy: host allowlist, secret-pattern scan of plaintext bodies, CONNECT tunnel. | **real code, no user.** Nothing starts it and `HTTPS_PROXY` is never injected into agent sessions, so in practice it sees no traffic. | v0.2: put it in the agent's path, or delete it. |
| `cop-ratelimit` | Per-session and per-user rate limits. | **library-only.** Fixed 60-second window on `Instant::now()`, no mocked clock, no persistence, so limits reset on every process start. | v0.2: sliding window with a mocked clock, or delete it. |

## Rules for this folder

1. Nothing here may be a dependency of a live crate. If you want to use one, move it back into
   `crates/` and put it in the workspace `members` list, with a test that proves the live path uses it.
2. A crate here may be deleted without ceremony. Nothing in the release depends on it.
3. Do not add features to a crate here while it sits here. The point of the move is to make the
   product honest about what it does; a feature in this folder is a feature that does not exist.
