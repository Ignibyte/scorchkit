#!/bin/bash
# =============================================================================
# enforce-pipeline-completion.sh -- Pipeline Document Archive Enforcement
# =============================================================================
#
# Blocks stopping when a pipeline document in active/ is marked complete
# but has not been moved to completed/.
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
source "$(dirname "$0")/lib-hook-helpers.sh"
if ! is_pipeline_session "$TRANSCRIPT_PATH"; then
    exit 0
fi

PIPELINE_DIR="docs/planning/pipeline"
ACTIVE_DIR="${PIPELINE_DIR}/active"
COMPLETED_DIR="${PIPELINE_DIR}/completed"

if [ ! -d "$ACTIVE_DIR" ]; then
    exit 0
fi

if [ -z "$TRANSCRIPT_PATH" ] || [ ! -f "$TRANSCRIPT_PATH" ]; then
    exit 0
fi

# --- Check if this session touched pipeline files ---
TOUCHED_PIPELINE=$(jq -r '
    [.[] | select(.role == "assistant") | .content[]? |
     select(.type == "tool_use") |
     select(.input.file_path != null) |
     .input.file_path // empty] |
    map(select(test("planning/pipeline/active/"))) |
    unique | .[]
' "$TRANSCRIPT_PATH" 2>/dev/null || true)

if [ -z "$TOUCHED_PIPELINE" ]; then
    exit 0
fi

VIOLATIONS=()

for doc in "$ACTIVE_DIR"/*.md; do
    [ -f "$doc" ] || continue

    FILENAME=$(basename "$doc")
    if [ "$FILENAME" = ".gitkeep" ] || [ "$FILENAME" = "README.md" ]; then
        continue
    fi

    IS_COMPLETE=false

    if grep -qi 'Status.*Complete' "$doc" 2>/dev/null; then
        if grep -qE '^\|.*Status.*\|.*Complete' "$doc" 2>/dev/null; then
            IS_COMPLETE=true
        fi
    fi

    for final_phase in 6 8; do
        if grep -qP "## Phase ${final_phase}:" "$doc" 2>/dev/null; then
            PHASE_SECTION=$(sed -n "/## Phase ${final_phase}:/,/## Phase/p" "$doc" 2>/dev/null | head -10)
            if echo "$PHASE_SECTION" | grep -q 'PASS'; then
                IS_COMPLETE=true
            fi
        fi
    done

    if [ "$IS_COMPLETE" = true ]; then
        VIOLATIONS+=("$FILENAME is marked complete but still in active/ — move it to completed/: mv $doc ${COMPLETED_DIR}/${FILENAME}")
    fi
done

if [ ${#VIOLATIONS[@]} -gt 0 ]; then
    if [ ! -d "$COMPLETED_DIR" ]; then
        echo "NOTE: Create the completed directory first: mkdir -p $COMPLETED_DIR" >&2
    fi

    {
        echo ""
        echo "STOP BLOCKED -- Completed pipeline documents must be archived:"
        echo ""
        for violation in "${VIOLATIONS[@]}"; do
            echo "  VIOLATION: $violation"
            echo ""
        done
        echo "Pipeline documents are NEVER deleted — they are moved to completed/ for history."
    } >&2
    exit 2
fi

exit 0
