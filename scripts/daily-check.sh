#!/usr/bin/env bash
# daily-check.sh: the log-only week daily check (Day 1 = 2026-10-27)
# Read-only: runs doctor and lists would-block cases. Output stays private in ~/.agentcop/daily.
set -u
cd ~/Desktop/agentcop || exit 1
CLI=./target/release/agentcop
START=2026-10-27
DAY=$(( ( $(date +%s) - $(date -d "$START" +%s) ) / 86400 + 1 ))
OUT_DIR=~/.agentcop/daily            # private: not in the repo
mkdir -p "$OUT_DIR" && chmod 700 "$OUT_DIR"
OUT="$OUT_DIR/day-$DAY-$(date +%F).txt"

{
  echo "=== Log-only week: Day $DAY of 7 ($(date '+%a %F %H:%M')) ==="
  echo; echo "--- doctor ---"
  $CLI doctor 2>&1
  echo; echo "--- would-block cases today ---"
  $CLI cases --today --would-block 2>&1 || true
  echo; echo "--- would-block cases since Day 1 (count) ---"
  $CLI cases --since "$START" --would-block 2>/dev/null | wc -l
} | tee "$OUT"
chmod 600 "$OUT"
echo; echo "Saved: $OUT"
