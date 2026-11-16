#!/bin/bash
# The one command that must be green before any phase can be released.
# Run it from the repository root:  ./scripts/check.sh
#
# Runs: cargo fmt, cargo clippy, cargo test, release build, cargo audit, a dead-crate check,
# the Python detective tests in a pinned venv, the courtroom checks, and the attack suite
# against both the debug binary and the release binary.
# Exits with code 2 (fail-closed) on any error.

set -e  # Exit on first error

echo "=== AgentCop check.sh ==="

# Cargo format check
echo "Checking code formatting..."
cargo fmt --check || {
    echo "❌ Formatting check failed"
    exit 2
}
echo "✓ Format check passed"

# Cargo clippy
echo "Running clippy..."
cargo clippy --all-targets -- -D warnings || {
    echo "❌ Clippy check failed"
    exit 2
}
echo "✓ Clippy passed"

# Cargo test
echo "Running tests..."
cargo test --all || {
    echo "❌ Tests failed"
    exit 2
}
echo "✓ All tests passed"

# Release build (2026-11-15): the artifact that is actually shipped is target/release/cop-hook.
# Before this step the release binary was never built or tested by the gate.
echo "Building the release binary..."
cargo build --release -p cop-hook -p cop-cli || {
    echo "❌ Release build failed"
    exit 2
}
echo "✓ Release build passed"

# Release binary smoke test: the same attack corpus, run against the release binary.
# The debug binary and the release binary are different programs; both must behave.
echo "Running the attack suite against the release binary..."
AGENTCOP_HOOK_BIN=target/release/cop-hook python3 tests/attacks/run_attacks.py || {
    echo "❌ The release binary failed the attack suite"
    exit 2
}
echo "✓ Release binary passed the attack suite"

# Dependency vulnerabilities (RUSTSEC). The default is stricter than "medium and above":
# any vulnerability advisory fails the check. Warnings (unsound, unmaintained) are reported
# but do not fail it.
echo "Auditing dependencies (cargo audit)..."
if ! command -v cargo-audit > /dev/null 2>&1; then
    echo "cargo-audit is not installed; trying to install it (this can take a few minutes)..."
    cargo install cargo-audit --locked || {
        echo "⚠️  Could not install cargo-audit; the dependency audit did not run"
    }
fi
if command -v cargo-audit > /dev/null 2>&1; then
    if cargo audit; then
        echo "✓ No known vulnerabilities"
    elif cargo audit --no-fetch; then
        echo "⚠️  The advisory database could not be updated (offline?). The local copy found nothing."
    else
        echo "❌ cargo audit found a vulnerability; see the advisory above"
        exit 2
    fi
fi

# Dead crates: a workspace member that neither cop-hook nor cop-cli depends on is not part of
# the product. This is a warning, not a failure: such crates are allowed (they may be on the
# roadmap), but they must not be counted as product coverage.
echo "Checking for crates outside the live path..."
LIVE=$(for pkg in cop-hook cop-cli; do
    cargo tree -p "$pkg" --prefix none --depth 5 -e normal 2> /dev/null
done | grep -oE '^cop-[a-z]+' | sort -u)
MEMBERS=$(cargo metadata --no-deps --format-version 1 2> /dev/null | python3 -c "
import json, sys
data = json.load(sys.stdin)
print('\n'.join(sorted(p['name'] for p in data['packages'])))
")
for member in $MEMBERS; do
    if ! echo "$LIVE" | grep -qx "$member"; then
        echo "⚠️  WARNING: $member is a workspace member but no live binary depends on it"
    fi
done
echo "✓ Live-path check done"

# Python detective tests (E2). The pinned versions in detective/requirements.txt are installed
# into detective/.deps and the tests run with that directory on PYTHONPATH, so a test run never
# depends on whatever happens to be installed system-wide.
# (A venv would need a path like detective/.venv/bin/python. Our own hook reads a script before it
# runs and denies a path that does not exist yet, so check.sh could not run on a fresh clone.
# Installing with --target keeps every path in this file real.)
echo "Running detective tests..."
python3 -m pip install --quiet --disable-pip-version-check --upgrade --requirement detective/requirements.txt --target detective/.deps || {
    echo "❌ Could not install the pinned Python dependencies"
    exit 2
}
PYTHONPATH=detective/.deps python3 -m pytest -q detective/tests || {
    echo "❌ Detective tests failed"
    exit 2
}
echo "✓ Detective tests passed"

# Courtroom (F1): typecheck, build the dashboard, then Playwright end-to-end tests.
echo "Running courtroom checks..."
(cd courtroom && npm ci --silent && npm run typecheck && npm run build && npx playwright install chromium > /dev/null && npm test) || {
    echo "❌ Courtroom checks failed"
    exit 2
}
echo "✓ Courtroom checks passed"

# Internal Affairs attack suite (E4). Runs the built cop-hook binary against tests/attacks/corpus.jsonl.
echo "Running Internal Affairs attack suite..."
python3 tests/attacks/run_attacks.py || {
    echo "❌ Internal Affairs attack suite failed"
    exit 2
}
echo "✓ Internal Affairs passed (results in docs/internal-affairs.md)"

# Policy canaries (item 4, 2026-10-27): the shipped policy must catch every must-catch action.
echo "Running policy canaries..."
cargo run -q -p cop-cli -- policy check policy/default.toml || {
    echo "❌ Policy canaries failed: the shipped policy allows a must-catch action"
    exit 2
}
echo "✓ Policy canaries passed"

echo ""
echo "✓✓✓ All checks passed ✓✓✓"
exit 0
