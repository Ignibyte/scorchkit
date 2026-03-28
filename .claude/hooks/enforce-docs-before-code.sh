#!/bin/bash
# =============================================================================
# enforce-docs-before-code.sh — Documentation-Before-Code Gate (PreToolUse)
# =============================================================================
#
# Blocks Edit and Write tool calls until search-architecture-docs has been called.
#
# Constitution References:
#   Section 16 — Architecture and framework documentation lookup is mandatory.
#   Section 15 — Enforcement: Hook checks are not rituals.
#
# Input: JSON on stdin with tool_name, tool_input, transcript_path
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

# --- Exempt non-code files ---
case "$NORMALIZED" in
    docs/*|tests/*|.claude/*)
        exit 0
        ;;
    *.toml|*.json|*.yaml|*.yml|*.xml|*.md|*.lock|*.env*)
        exit 0
        ;;
    CLAUDE.md|CONSTITUTION.md|rustfmt.toml|deny.toml|clippy.toml)
        exit 0
        ;;
    Cargo.toml|Cargo.lock|config.toml)
        exit 0
        ;;
    *.sh)
        exit 0
        ;;
esac

# --- Get transcript path ---
TRANSCRIPT_PATH=$(echo "$INPUT" | jq -r '.transcript_path // empty')
if [ -z "$TRANSCRIPT_PATH" ] || [ ! -f "$TRANSCRIPT_PATH" ]; then
    exit 0
fi

TOOL_CALLS=$(get_tool_calls "$TRANSCRIPT_PATH")

tool_called() {
    tool_was_called "$TOOL_CALLS" "$1"
}

# --- Skip non-pipeline sessions ---
if ! is_pipeline_session "$TRANSCRIPT_PATH"; then
    exit 0
fi

# =============================================================================
# CHECK: search-architecture-docs must have been called
# =============================================================================
if ! tool_called "search-architecture-docs"; then
    {
        echo ""
        echo "BLOCKED — You must call search-architecture-docs before writing code."
        echo ""
        echo "Constitution Section 16 requires documentation lookup BEFORE implementation,"
        echo "not after. Search the docs now — your implementation should be informed"
        echo "by project patterns and architecture decisions."
        echo ""
        echo "Call: search-architecture-docs (list all, or query for relevant patterns)"
        echo "Then retry your edit/write."
    } >&2
    exit 2
fi

exit 0
