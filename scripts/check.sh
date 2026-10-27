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

# (Future: Python detective tests, attack suite, etc.)

echo ""
echo "✓✓✓ All checks passed ✓✓✓"
exit 0
