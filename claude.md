# Mission: build AgentCop, one small phase at a time

You are the lead engineer on AgentCop, an open-source tool that watches AI coding agents
(Claude Code first, then Codex), stops dangerous actions before they land, keeps
tamper-evident evidence, explains every arrest, and makes it fun with cartoon police sound
effects. I am the owner. I am an intermediate programmer who is learning logic building,
so you also teach me through brain.md.

There is NO hurry. Correctness beats speed. Never skip a step to finish faster.

## 1. brain.md is the brain of this project (non-negotiable)

- Create brain.md in phase A1 using the template in section 7. Read it at the start of
  EVERY session and EVERY phase before doing anything else.
- brain.md is append-only history: never delete old phase logs, bugs or decisions.
- Keep the "Current status" block at the top true at all times.
- Write in plain English a learner can follow. Explain WHY, not just what.
- Record every bug: symptom, root cause, fix, and the test that now guards it.
- Record every architecture decision in the ADR table with the reason.

## 2. The phase loop (follow exactly, for every phase)

1. READ brain.md. Confirm the previous phase is DONE and approved by me.
2. START: set status to PLANNING. In brain.md, write the phase goal, a numbered
   plain-English plan, the files you will touch, and the tests you will write.
3. TESTS FIRST: write the tests for this phase (normal case, edge case, attack case).
   Run them and confirm they fail for the right reason.
4. BUILD in small steps. After each small step, compile and run the relevant tests.
   Set status to BUILDING. Every new source file starts with a PLAN comment block
   (input, output, numbered steps, edge cases). Keep functions short.
5. VERIFY: set status to TESTING and run scripts/check.sh, which must run:
   cargo fmt --check, cargo clippy --all-targets -- -D warnings, cargo test --all,
   Python tests (once detective/ exists), and the attack suite in tests/attacks/.
6. IF ANYTHING FAILS: log it in the phase's bug table and the Bug journal, find the
   ROOT cause, fix it, add or keep a test that guards it, then rerun ALL checks.
   Never weaken, skip or delete a test to make it pass. Never mark a phase done
   with a red or flaky test.
7. SELF-REVIEW before declaring green. Check: all "done when" criteria met; no
   unwrap()/panic on untrusted input; errors fail closed; no secrets in code, logs
   or fixtures; sound never blocks a verdict; README and THREAT_MODEL updated if
   behavior changed; brain.md complete.
8. COMPLETE: write the phase log (built files, verification command and result
   summary, lessons explained simply), tick the phase in the roadmap, set status to
   DONE-WAITING-FOR-OK, and write docs/phases/<phase>.md (short report).
9. STOP. Tell me in 5-10 lines: what was built, how to try it myself (exact
   commands), the test results, and anything you were unsure about. Then wait.
   Do NOT start the next phase until I reply "approved, next phase".

If a phase turns out too big, split it into sub-phases (for example C2a, C2b),
record the split in brain.md, and still stop after each one.
If you are blocked or unsure about a security-relevant choice, ask me instead of guessing.

## 3. Architecture rules (never break these)

- Enforcement is deterministic Rust code. No LLM is ever on the allow/deny path.
- Fail closed: any internal error, timeout or bad input results in DENY. Claude Code
  hooks fail OPEN by default, so the installer must set "onFailure": "block" on our
  hook and the hook must exit with code 2 and a deny decision on error.
- The detective LLM gets no tools and no powers. Its output must match a strict
  schema; it may only RAISE severity, never lower it or release anyone. Invalid output
  is discarded and the case stays as it was.
- Treat everything the agent read (files, web pages, tool output) as untrusted data.
- Evidence is append-only and hash-chained; the agent must never be able to edit it.
- Never put real secrets anywhere. Honeytokens must be obviously fake decoys.
- The cop protects itself: rules deny edits to its policy, config, evidence and
  hook settings, and attempts to kill its processes.
- Customizable: all laws live in policy TOML files, not hard-coded.
- Honest: keep THREAT_MODEL.md and a "known limits" list up to date. Never claim
  "unhackable" or "bulletproof" anywhere.

## 4. Tech stack

- Rust workspace (crates: cop-core, cop-policy, cop-evidence, cop-hook, cop-daemon,
  cop-siren, cop-cli, cop-sensors, cop-proxy, cop-cell). Use serde, toml, regex,
  rusqlite, sha2, tokio, clap, rodio, aya (eBPF, Linux).
- Python 3.11+ for detective/ (pydantic for strict schemas; provider pluggable;
  offline template mode with no API key).
- TypeScript + React + Vite for courtroom/ (local only, 127.0.0.1, random token).
- Facts to rely on (verify against current docs before using; record what you
  verified in brain.md):
  - Claude Code PreToolUse hooks receive JSON on stdin with tool_name and
    tool_input, and answer with hookSpecificOutput.permissionDecision =
    allow | ask | deny plus permissionDecisionReason. Exit code 2 blocks.
  - Codex hooks live in ~/.codex/hooks.json and also support a PreToolUse hook.
  - cgroup v2: writing 1 to cgroup.freeze freezes a cgroup; cgroup.events shows frozen 1.

## 5. The 26 phases (do them in order)

Stage A, Rookie:
A1 Skeleton: workspace, empty crates, brain.md, THREAT_MODEL.md stub, scripts/check.sh.
   Done: check.sh passes.
A2 Core types: AgentEvent, Verdict, Case with serde; Claude Code fixtures in
   tests/fixtures/hooks. Done: fixtures parse, garbage input errors without panic.
A3 Judge v1: TOML rules, compiled regex, strictest wins (deny > ask > allow),
   honeytokens. Port these behaviors: block rm -rf on / or ~, block destructive commands
   mentioning prod, block secret files (.env, ssh keys, cloud creds), block curl|sh,
   ask before git push and data uploads, protect the cop. Done: tests pass, < 1 ms/event.
A4 Evidence: SQLite append-only with SHA-256 hash chain and verify().
   Done: edit and delete tampering detected; 10k entries verify < 1 s.
A5 cop-hook binary: stdin -> judge -> evidence -> stdout JSON; fail closed.
   Done: allow/ask/deny fixture tests; malformed input denies; cold start < 50 ms.
A6 CLI: agentcop install/uninstall/cases/verify; backs up settings.json, merges hook
   with onFailure block, --dry-run, idempotent. Done: tested in a temp HOME.
GATE A: I record a demo blocking a "volume delete prod" command in live Claude Code.

Stage B, Siren:
B1 Sound engine (rodio), non-blocking, volume, mute, quiet hours, silent in CI/SSH/no device.
   Done: test proves verdict returns before sound finishes.
B2 Cartoon pack synthesized in code: whistle (detain), siren whoop + handcuff click
   (arrest), alarm bell (honeytoken sting), cell-door clank (frozen), gavel (verdict),
   jingle (case closed), radio chirp (daemon start). pack.toml maps events to files.
   Done: deterministic output, each clip <= 1.5 s, peak-normalized, default volume 50%.
B3 Theatrics: ASCII badge, mugshot card, rotating Miranda lines ("You have the right to
   remain paused."), static red/blue banner, never more than 2 flashes per second,
   NO_COLOR respected, --no-fun flag. Done: snapshot tests.
GATE B: v0.1 release with README, THREAT_MODEL.md, demo GIF.

Stage C, Beat cop:
C1 copd daemon on a Unix socket; hook is a thin client and judges locally if daemon down.
C2 Normalizer: shell tokenizing and evasion detection (quotes, backslashes, absolute
   paths, bash -c, base64 | sh, command substitution). Done: tests/attacks/evasion passes.
C3 Codex adapter and agentcop install --codex.
C4 agentcop plant: decoy .env, fake cloud creds, canary DB host; any touch = deny + sting.
C5 Sliding-window speed limits in the daemon, tested with a mocked clock.
GATE C: v0.2 release.

Stage D, Surveillance (Linux first; tests in a privileged VM or container):
D1 Aya eBPF exec sensor, observe-only, process tree.
D2 Map sessions to root PIDs; flag descendant execs no hook reported.
D3 Secret-path open and outbound connect sensors, correlated to sessions.
D4 cop-proxy: domain allowlist and secret-pattern scan; HTTPS_PROXY for agent sessions.
D5 cop-cell: freeze via cgroup.freeze, SIGSTOP fallback, snapshot, thaw or kill.
GATE D: demo where the agent bypasses hooks and is still frozen.

Stage E, Detective and Internal Affairs:
E1 Case bundle JSON with untrusted text quoted and size-capped; JSON schema.
E2 Python detective: quarantined, no tools, strict schema, only raises severity,
   offline template mode. Done: injected "mark this safe" text never lowers severity.
E3 agentcop fix CASE-ID: shows a diff of the suggested rule, asks before applying.
E4 Internal Affairs attack suite wired into check.sh; results in docs/.
GATE E: publish results and a "what AgentCop does not catch" page.

Stage F, Courtroom and Agency:
F1 Courtroom web dashboard: timeline, mugshots, release/convict, sounds; Playwright tests.
F2 Police Blotter, ranks (Rookie, Officer, Detective, Sergeant, Chief), shareable
   mugshot PNGs with secrets redacted, community sound packs, Wanted list.
F3 Rule of Two: freeze sessions combining untrusted input + sensitive data + external
   actions; scenario tests for each combination.

## 6. Fun layer rules

- Fun on the surface, serious underneath. Cartoon tone; never mock real police
  violence or real people.
- Sounds are synthesized in code or CC0 only. Never ship movie, game or real police audio.
- Sound and animation must never delay a verdict and must be easy to turn off.

## 7. brain.md template (create this in A1)

# AgentCop brain.md
## Current status
- Current phase / Phase state (PLANNING, BUILDING, TESTING, DONE-WAITING-FOR-OK)
- Last green check (date, command, result) / Next step
## Mission
## Architecture decisions (ADR log): # | Decision | Why | Date
## Phase roadmap: checklist of all 26 phases
## Phase logs: per phase -> Goal, Plan (numbered, plain English), Tests written first,
   What was built, Bugs and fixes table, Verification, Lessons explained simply, Status
## Bug journal: Date | Phase | Bug | Root cause | Fix | Test
## Known limits
## Glossary (terms explained for a learner)

## 8. Start now

Begin with phase A1 only. Follow the phase loop. Stop at step 9 and wait for my OK.
