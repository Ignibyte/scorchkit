#!/bin/bash
# =============================================================================
# enforce-tests-ran.sh — Test Execution Verification (Stop Hook)
# =============================================================================
#
# Blocks stopping unless cargo test was actually EXECUTED in the transcript.
# Writing test files without running them is not testing.
#
# Constitution References:
#   Section 7  — Testing Standards: NEVER mark PASS if tests didn't actually run
#   Section 15 — Enforcement: Transcript is the source of truth
#
# Input: JSON on stdin with session_id, stop_hook_active, transcript_path
# Exit:  0 = allow stop, 2 = block with feedback on stderr
# =============================================================================

set -euo pipefail

INPUT=$(cat)

STOP_ACTIVE=$(echo "$INPUT" | jq -r '.stop_hook_active // false')
if [ "$STOP_ACTIVE" = "true" ]; then
    exit 0
fi

if ! command -v jq &>/dev/null; then
    exit 0
fi

TRANSCRIPT_PATH=$(echo "$INPUT" | jq -r '.transcript_path // empty')
if [ -z "$TRANSCRIPT_PATH" ] || [ ! -f "$TRANSCRIPT_PATH" ]; then
    exit 0
fi

source "$(dirname "$0")/lib-hook-helpers.sh"

if ! is_pipeline_session "$TRANSCRIPT_PATH"; then
    exit 0
fi

VIOLATIONS=()

# =============================================================================
# CHECK 1: cargo test execution
# =============================================================================
CARGO_TEST_RUNS=$(jq '
    [.[] | select(.role == "assistant") | .content[]? |
     select(.type == "tool_use") | select(.name == "Bash") |
     .input.command // empty] |
    map(select(test("cargo test"))) |
    length
' "$TRANSCRIPT_PATH" 2>/dev/null || echo "0")

if [ "$CARGO_TEST_RUNS" = "0" ]; then
    VIOLATIONS+=("cargo test was NEVER EXECUTED. You must run 'cargo test' (or 'cargo test --workspace') and report actual results. Constitution Section 7: 'NEVER mark PASS if tests didn't actually run.'")
fi

# =============================================================================
# CHECK 2: Sanity — at least one Bash command was run
# =============================================================================
TOTAL_BASH=$(jq '
    [.[] | select(.role == "assistant") | .content[]? |
     select(.type == "tool_use") | select(.name == "Bash")] |
    length
' "$TRANSCRIPT_PATH" 2>/dev/null || echo "0")

if [ "$TOTAL_BASH" = "0" ]; then
    VIOLATIONS+=("ZERO Bash commands were executed. You must use the Bash tool to run test commands. MCP calls alone do not constitute testing.")
fi

# =============================================================================
# VERDICT
# =============================================================================
if [ ${#VIOLATIONS[@]} -gt 0 ]; then
    {
        echo ""
        echo "STOP BLOCKED — Test execution verification failed:"
        echo ""
        for violation in "${VIOLATIONS[@]}"; do
            echo "  VIOLATION: $violation"
            echo ""
        done
        echo "You MUST actually RUN tests before stopping. Command:"
        echo "  cargo test"
        echo ""
        echo "Constitution Section 15: 'Transcript is the source of truth.'"
        echo "If it didn't happen in the transcript, it didn't happen."
    } >&2
    exit 2
fi

exit 0
