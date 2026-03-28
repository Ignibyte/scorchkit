#!/bin/bash
# =============================================================================
# lib-hook-helpers.sh — Shared helper functions for enforcement hooks
# =============================================================================
#
# Source this file from other hooks to get common detection functions.
# Usage: source "$(dirname "$0")/lib-hook-helpers.sh"
# =============================================================================

# --- Project root detection ---
PROJECT_ROOT=$(git rev-parse --show-toplevel 2>/dev/null || pwd)

# --- Normalize a path relative to PROJECT_ROOT ---
normalize_path() {
    echo "$1" | sed "s|^${PROJECT_ROOT}/||"
}

# --- Detect project framework ---
detect_framework() {
    if [ -f "${PROJECT_ROOT}/Cargo.toml" ]; then
        echo "rust"
    else
        echo "unknown"
    fi
}

# --- Check if a tool is installed ---
has_tool() {
    [ -f "${PROJECT_ROOT}/$1" ] || command -v "$1" &>/dev/null
}

# --- Detect if this is a pipeline/agent session ---
# Checks the session transcript for MCP tool calls. Returns 0 (true) if MCP
# tools were found, 1 (false) if not.
is_pipeline_session() {
    local transcript_path="$1"

    if [ -z "$transcript_path" ] || [ ! -f "$transcript_path" ]; then
        return 1
    fi

    local mcp_count
    mcp_count=$(jq '
        [.[] | select(.role == "assistant") | .content[]? |
         select(.type == "tool_use") |
         .name // empty |
         sub("^mcp__.*__"; "")] |
        map(select(
            test("^(bootstrap|recall|learn|search-patterns|search-knowledge|pipeline-advance|pipeline-context|pipeline-status|ticket-create|ticket-update|ticket-claim|ticket-next|ticket-close|ticket-comment|save-generation-trace|report-failure|search-architecture-docs|search-docs|example-feedback|upload-golden-example|architecture-set|architecture-get|architecture-list|promote-knowledge|scan-project|sync-agents|bootstrap-project|compare-pipeline-hashes|contribute-pipeline)$")
        )) | length
    ' "$transcript_path" 2>/dev/null || echo "0")

    if [ "$mcp_count" = "0" ]; then
        return 1
    fi

    return 0
}

# --- Extract all unique tool names from transcript ---
get_tool_calls() {
    local transcript_path="$1"

    jq -r '
        [.[] | select(.role == "assistant") | .content[]? |
         select(.type == "tool_use") | .name // empty |
         sub("^mcp__.*__"; "")]
        | unique | .[]
    ' "$transcript_path" 2>/dev/null || true
}

# --- Check if a specific tool was called ---
tool_was_called() {
    local tool_calls="$1"
    local tool_name="$2"

    echo "$tool_calls" | grep -q "^${tool_name}$"
}

# --- Get current pipeline phase from active pipeline docs ---
get_current_phase() {
    local active_dir="${PROJECT_ROOT}/docs/planning/pipeline/active"

    if [ ! -d "$active_dir" ]; then
        echo ""
        return
    fi

    for doc in "$active_dir"/*.md; do
        [ -f "$doc" ] || continue
        local filename
        filename=$(basename "$doc")
        [ "$filename" = ".gitkeep" ] || [ "$filename" = "README.md" ] && continue

        local phase
        phase=$(grep -oP '^\|\s*\*\*Status\*\*\s*\|.*Phase\s+\K[0-9]+' "$doc" 2>/dev/null | head -1)
        if [ -n "$phase" ]; then
            echo "$phase"
            return
        fi
    done

    echo ""
}
