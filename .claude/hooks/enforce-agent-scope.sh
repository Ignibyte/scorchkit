#!/bin/bash
# =============================================================================
# enforce-agent-scope.sh — Phase-Based Write Scope Enforcement (PreToolUse)
# =============================================================================
#
# Blocks writes to files that don't match the current pipeline phase's scope.
#
# Constitution References:
#   Section 4  — Phase Scope: Each phase has a defined boundary
#   Section 15 — Enforcement: Scope boundaries are hard walls
#
# Input: JSON on stdin with tool_name, tool_input (file_path)
# Exit:  0 = allow, 2 = block with feedback on stderr
# =============================================================================

set -euo pipefail

INPUT=$(cat)

if ! command -v jq &>/dev/null; then
    exit 0
fi

FILE_PATH=$(echo "$INPUT" | jq -r '.tool_input.file_path // empty')

if [ -z "$FILE_PATH" ]; then
    exit 0
fi

source "$(dirname "$0")/lib-hook-helpers.sh"

NORMALIZED=$(normalize_path "$FILE_PATH")

# --- Always allow: pipeline documents, hook scripts, command files ---
case "$NORMALIZED" in
    docs/planning/pipeline/*) exit 0 ;;
    .claude/commands/*) exit 0 ;;
    .claude/hooks/*) exit 0 ;;
    .claude/settings.json) exit 0 ;;
    CLAUDE.md) exit 0 ;;
    CONSTITUTION.md) exit 0 ;;
    CHANGELOG.md) exit 0 ;;
esac

CURRENT_PHASE=$(get_current_phase)

# If no active pipeline, allow all writes (not in pipeline mode)
if [ -z "$CURRENT_PHASE" ]; then
    exit 0
fi

case "$CURRENT_PHASE" in
    # Phase 1 (Plan) — only pipeline docs
    1)
        {
            echo ""
            echo "WRITE BLOCKED — Phase 1 (Plan) cannot write to: $NORMALIZED"
            echo "Phase 1 only creates pipeline documents in docs/planning/pipeline/."
            echo "Run /design to advance to Phase 2 before making other changes."
        } >&2
        exit 2
        ;;

    # Phase 2 (Design) — only pipeline docs and architecture docs
    2)
        case "$NORMALIZED" in
            docs/*) exit 0 ;;
            *)
                {
                    echo ""
                    echo "WRITE BLOCKED — Phase 2 (Design) cannot write to: $NORMALIZED"
                    echo "Phase 2 only writes design documents (docs/). No code."
                    echo "Run /implement to advance to Phase 3 before writing code."
                } >&2
                exit 2
                ;;
        esac
        ;;

    # Phase 3 (Implement) — broad access
    3)
        exit 0
        ;;

    # Phase 4 (Validate) — may fix bugs found during validation
    4)
        exit 0
        ;;

    # Phase 5 (Verify) — should NOT be writing code, only pipeline docs
    5)
        case "$NORMALIZED" in
            docs/*) exit 0 ;;
            tests/*) exit 0 ;;
            *)
                {
                    echo ""
                    echo "WRITE BLOCKED — Phase 5 (Verify) cannot write to: $NORMALIZED"
                    echo "Phase 5 runs the full test suite. It should not modify source code."
                    echo "If tests fail, go back to /implement to fix, then re-run /validate and /verify."
                } >&2
                exit 2
                ;;
        esac
        ;;

    # Phase 6 (Complete) — docs, changelog, pipeline archival only
    6)
        case "$NORMALIZED" in
            docs/*) exit 0 ;;
            CHANGELOG*) exit 0 ;;
            *)
                {
                    echo ""
                    echo "WRITE BLOCKED — Phase 6 (Complete) cannot write to: $NORMALIZED"
                    echo "Phase 6 updates documentation and changelog only. No code changes."
                    echo "If code changes are needed, go back to /implement."
                } >&2
                exit 2
                ;;
        esac
        ;;

    # Unknown phase — allow
    *)
        exit 0
        ;;
esac
