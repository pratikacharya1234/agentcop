# Security policy

AgentCop is a safety tool, so a bug in it can matter. Please report security problems privately.

## How to report
Use GitHub's private vulnerability reporting: open the repository's **Security** tab, then **Report a vulnerability**. Do not open a public issue for a vulnerability.

## What to include
- The version or commit, and your platform.
- The exact event or command that gets through (or is wrongly blocked), and what you expected.
- Whether you can reproduce it with `docs/demo/gate-a-replay.sh` or the attack corpus (`tests/attacks/corpus.jsonl`).

## What to expect
This is a hobby project, maintained by one person. Expect a reply within a week. Fixes land on the main branch with a test that fails before the fix and passes after.

## Out of scope
- Anything that needs root on the machine, since root can already change the hook, the policy and the evidence file. See [THREAT_MODEL.md](THREAT_MODEL.md).
- Known gaps listed in [docs/what-agentcop-does-not-catch.md](docs/what-agentcop-does-not-catch.md). Those are known, but a new bypass of a rule is still worth reporting.
