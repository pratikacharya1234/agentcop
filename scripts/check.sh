#!/bin/bash
# The one command that must be green before any phase can be released.
# Runs: cargo fmt, cargo clippy, cargo test, (later: python tests, attack suite)
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

# Python detective tests (E2). Fail closed like the rest.
echo "Running detective tests..."
(cd detective && python3 -m pytest -q) || {
    echo "❌ Detective tests failed"
    exit 2
}
echo "✓ Detective tests passed"

# Courtroom (F1): typecheck, build the dashboard, then Playwright end-to-end tests.
echo "Running courtroom checks..."
(cd courtroom && npm ci --silent && npm run typecheck && npm run build && npx playwright install chromium >/dev/null && npm test) || {
    echo "❌ Courtroom checks failed"
    exit 2
}
echo "✓ Courtroom checks passed"

# Internal Affairs attack suite (E4). Runs the built cop-hook binary against tests/attacks/corpus.jsonl.
echo "Running Internal Affairs attack suite..."
cargo build -p cop-hook || {
    echo "❌ Building cop-hook failed"
    exit 2
}
python3 tests/attacks/run_attacks.py || {
    echo "❌ Internal Affairs attack suite failed"
    exit 2
}
echo "✓ Internal Affairs passed (results in docs/internal-affairs.md)"

echo ""
echo "✓✓✓ All checks passed ✓✓✓"
exit 0
