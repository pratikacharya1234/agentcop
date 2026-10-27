#!/usr/bin/env bash
# Scripted replay of the Gate A block, for recording a demo.
# This is NOT a live Claude Code session. It installs the hook into a throwaway HOME,
# then sends the same event Claude Code sends for `railway volume delete prod-db`.
# The real command is never run.
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
AGENTCOP="$ROOT/target/release/agentcop"
HOOK="$ROOT/target/release/cop-hook"
DEMO_HOME="$(mktemp -d)"
trap 'rm -rf "$DEMO_HOME"' EXIT

[ -x "$AGENTCOP" ] && [ -x "$HOOK" ] || { echo "build first: cargo build --release -p cop-cli -p cop-hook"; exit 2; }
mkdir -p "$DEMO_HOME/.claude" && echo '{}' > "$DEMO_HOME/.claude/settings.json"

echo "\$ agentcop install   (throwaway HOME)"
HOME="$DEMO_HOME" "$AGENTCOP" install >/dev/null

echo "\$ Claude Code asks to run: railway volume delete prod-db"
EVENT='{"hook_event_name":"PreToolUse","session_id":"gate-a-replay","timestamp":"2026-10-23T12:00:00Z","tool_name":"Bash","tool_input":{"command":"railway volume delete prod-db"}}'
RESULT="$(echo "$EVENT" | HOME="$DEMO_HOME" "$HOOK" 2>/dev/null)"
echo "$RESULT" | python3 -c 'import json,sys; d=json.load(sys.stdin)["hookSpecificOutput"]; print("decision:", d["permissionDecision"]); print("reason:  ", d["permissionDecisionReason"])'

echo "\$ agentcop cases"
HOME="$DEMO_HOME" "$AGENTCOP" cases
