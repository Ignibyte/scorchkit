#!/bin/bash
# =============================================================================
# enforce-completion.sh — Pipeline Phase Completion Enforcement
# =============================================================================
#
# Blocks the conversation from stopping until required Forge MCP calls have
# been made for the current pipeline phase.
#
# Constitution References:
#   §9  — Knowledge Recording: learn + report-failure before completing
#   §11 — Recall Before Action: NEVER skip recall
#   §15 — Anti-Circumvention: Evidence over claims
#   §16 — Architecture/framework doc lookup is mandatory
#
# Input: JSON on stdin with session_id, stop_hook_active, transcript_path
# Exit:  0 = allow stop, 2 = block with feedback on stderr
# =============================================================================

set -euo pipefail

INPUT=$(cat)

# --- Safety: prevent infinite loops ---
STOP_ACTIVE=$(echo "$INPUT" | jq -r '.stop_hook_active // false')
if [ "$STOP_ACTIVE" = "true" ]; then
    exit 0
fi

TRANSCRIPT_PATH=$(echo "$INPUT" | jq -r '.transcript_path // empty')
if [ -z "$TRANSCRIPT_PATH" ] || [ ! -f "$TRANSCRIPT_PATH" ]; then
    exit 0
fi

if ! command -v jq &>/dev/null; then
    exit 0
fi

source "$(dirname "$0")/lib-hook-helpers.sh"
if ! is_pipeline_session "$TRANSCRIPT_PATH"; then
    exit 0
fi

TOOL_CALLS=$(get_tool_calls "$TRANSCRIPT_PATH")

tool_called() {
    tool_was_called "$TOOL_CALLS" "$1"
}

CURRENT_PHASE=$(get_current_phase)

# Detect what kind of work was done
WROTE_CODE=$(jq -r '
    [.[] | select(.role == "assistant") | .content[]? |
     select(.type == "tool_use") |
     select(.name == "Write" or .name == "Edit") |
     select(.input.file_path != null) |
     .input.file_path // empty] |
    map(select(test("\\.(rs|toml)$"))) |
    length
' "$TRANSCRIPT_PATH" 2>/dev/null || echo "0")

WROTE_PIPELINE=$(jq -r '
    [.[] | select(.role == "assistant") | .content[]? |
     select(.type == "tool_use") |
     select(.name == "Write" or .name == "Edit") |
     select(.input.file_path != null) |
     .input.file_path // empty] |
    map(select(test("planning/pipeline/"))) |
    length
' "$TRANSCRIPT_PATH" 2>/dev/null || echo "0")

TOTAL_BASH=$(jq '
    [.[] | select(.role == "assistant") | .content[]? |
     select(.type == "tool_use") | select(.name == "Bash")] |
    length
' "$TRANSCRIPT_PATH" 2>/dev/null || echo "0")

MISSING=()

# =============================================================================
# TIER 1: UNIVERSAL — Every pipeline session, no exceptions
# =============================================================================

if ! tool_called "recall"; then
    MISSING+=("recall — Constitution §11: Every phase MUST call recall with the appropriate agent name and phase number before starting work. Prevention rules from recall are BINDING.")
fi

if ! tool_called "learn"; then
    MISSING+=("learn — Constitution §9: Every phase MUST call learn before finishing. Record what was discovered — lessons, patterns, or a clean-execution confirmation.")
fi

if ! tool_called "bootstrap"; then
    MISSING+=("bootstrap — Required context loading. Call bootstrap to get project context, architecture decisions, and active patterns.")
fi

# =============================================================================
# TIER 2: CODE/DESIGN WORK — When files were written
# =============================================================================

if [ "$WROTE_CODE" -gt 0 ] 2>/dev/null || [ "$WROTE_PIPELINE" -gt 0 ] 2>/dev/null; then
    if ! tool_called "search-architecture-docs"; then
        MISSING+=("search-architecture-docs — Constitution §16: Architecture documentation lookup is mandatory before writing code or designs.")
    fi
fi

# =============================================================================
# TIER 3: PHASE-SPECIFIC
# =============================================================================

case "$CURRENT_PHASE" in
    2)
        if ! tool_called "architecture-set"; then
            MISSING+=("architecture-set — Design phase must record architectural decisions. Call architecture-set with key-value pairs for each decision made.")
        fi
        ;;
    3)
        if [ "$TOTAL_BASH" = "0" ] 2>/dev/null; then
            MISSING+=("Bash tool — Implementation phase ran ZERO Bash commands. You must run cargo fmt, cargo clippy, and cargo test via the Bash tool.")
        fi
        ;;
    4)
        if [ "$TOTAL_BASH" = "0" ] 2>/dev/null; then
            MISSING+=("Bash tool — Validation phase ran ZERO Bash commands. You must independently re-run cargo fmt, cargo clippy, and cargo test.")
        fi
        ;;
    5)
        if [ "$TOTAL_BASH" = "0" ] 2>/dev/null; then
            MISSING+=("Bash tool — Verify phase ran ZERO Bash commands. You must run the full cargo test suite.")
        fi
        ;;
    6)
        if ! tool_called "save-generation-trace"; then
            MISSING+=("save-generation-trace — Phase 6 (Complete) MUST record the After-Action Review. Call save-generation-trace with pipeline_type=\"work\", work_title, and component_types.")
        fi
        ;;
esac

# =============================================================================
# TIER 4: RECIPROCITY
# =============================================================================

if tool_called "search-patterns" && ! tool_called "example-feedback"; then
    MISSING+=("example-feedback — You called search-patterns but never reported whether the examples were useful. Call example-feedback with outcome.")
fi

# =============================================================================
# VERDICT
# =============================================================================

if [ ${#MISSING[@]} -gt 0 ]; then
    {
        echo ""
        echo "STOP BLOCKED — Required Forge MCP calls not completed (Phase ${CURRENT_PHASE:-?}):"
        echo ""
        for item in "${MISSING[@]}"; do
            echo "  MISSING: $item"
            echo ""
        done
        echo "Complete ALL missing calls before stopping."
        echo "Constitution §9 (Knowledge Recording) and §11 (Recall Before Action) are non-negotiable."
    } >&2
    exit 2
fi

exit 0
