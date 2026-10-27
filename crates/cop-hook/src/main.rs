//! Border patrol: tiny binary run by Claude Code hooks
//!
//! PLAN:
//! 1. Read JSON from stdin (PreToolUse hook input)
//! 2. Pass to judge
//! 3. Store verdict in evidence
//! 4. Output JSON verdict to stdout
//! 5. Exit code 2 on any error (fail-closed)
//! 6. Cold start <50ms

fn main() {
    // Phase A1: skeleton only
}
