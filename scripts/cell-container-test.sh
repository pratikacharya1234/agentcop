#!/usr/bin/env bash
# Run cop-cell tests, including the real cgroup v2 test, inside a privileged container.
# The container gets its own cgroup namespace, so the real-cgroup test writes only there.
# Needs docker. Set AGENTCOP_RUST_IMAGE to pick a different rust image.
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
IMAGE="${AGENTCOP_RUST_IMAGE:-rust:1}"

docker run --rm --privileged \
  -v "$ROOT:/src:ro" \
  -w /src \
  -e CARGO_TARGET_DIR=/tmp/target \
  -e AGENTCOP_CELL_CGROUP_ROOT=/sys/fs/cgroup \
  "$IMAGE" \
  cargo test -p cop-cell -- --nocapture
