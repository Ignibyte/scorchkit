#!/bin/bash
# =============================================================================
# enforce-pipeline-checklist.sh — Final Pipeline Completion Checklist
# =============================================================================
#
# Runs as a Stop hook at Phase 6. Independently verifies that every requirement
# across all phases was actually met.
#
# Constitution References:
#   §9  — Knowledge Recording
#   §14 — Code Quality Standards
#   §15 — Anti-Circumvention: Evidence over claims
#
# Input: JSON on stdin with session_id, stop_hook_active, transcript_path
# Exit:  0 = allow stop, 2 = block with feedback on stderr
# =============================================================================

set -euo pipefail

if [ -f "$HOME/.cargo/env" ]; then
    source "$HOME/.cargo/env"
fi

source "$(dirname "$0")/lib-hook-helpers.sh"

INPUT=$(cat)

STOP_ACTIVE=$(echo "$INPUT" | jq -r '.stop_hook_active // false')
if [ "$STOP_ACTIVE" = "true" ]; then
    exit 0
fi

if ! command -v jq &>/dev/null; then
    exit 0
fi

TRANSCRIPT_PATH=$(echo "$INPUT" | jq -r '.transcript_path // empty')
if [ -n "$TRANSCRIPT_PATH" ] && [ -f "$TRANSCRIPT_PATH" ]; then
    if ! is_pipeline_session "$TRANSCRIPT_PATH"; then
        exit 0
    fi
fi

# --- Only activate at Phase 6 (Complete) ---
CURRENT_PHASE=$(get_current_phase)
if [ "$CURRENT_PHASE" != "6" ]; then
    exit 0
fi

# --- Find the active pipeline document ---
PIPELINE_DOC=""
ACTIVE_DIR="${PROJECT_ROOT}/docs/planning/pipeline/active"
for doc in "$ACTIVE_DIR"/WORK-*.md "$ACTIVE_DIR"/PIPELINE-*.md; do
    [ -f "$doc" ] || continue
    PIPELINE_DOC="$doc"
    break
done

if [ -z "$PIPELINE_DOC" ]; then
    exit 0
fi

FAILURES=()
WARNINGS=()

# =============================================================================
# SECTION 1: Pipeline Document Integrity
# =============================================================================

if ! grep -q "Forge Ticket ID" "$PIPELINE_DOC" 2>/dev/null; then
    FAILURES+=("PIPELINE_DOC: Missing 'Forge Ticket ID' in header.")
fi

PHASE_STATUSES=$(grep '^\*\*Status:\*\*' "$PIPELINE_DOC" 2>/dev/null || true)
NOT_STARTED=$(echo "$PHASE_STATUSES" | grep -c "Not Started" || true)
FAILS=$(echo "$PHASE_STATUSES" | grep -c "FAIL" || true)

if [ "$NOT_STARTED" -gt 1 ] 2>/dev/null; then
    FAILURES+=("PIPELINE_DOC: $NOT_STARTED phases still show 'Not Started'. All phases 1-5 must be PASS.")
fi

if [ "$FAILS" -gt 0 ] 2>/dev/null; then
    FAILURES+=("PIPELINE_DOC: $FAILS phase(s) show 'FAIL'. All phases must be PASS.")
fi

if grep -q "cargo fmt.*Not run\|cargo clippy.*Not run\|cargo test.*Not run" "$PIPELINE_DOC" 2>/dev/null; then
    FAILURES+=("PIPELINE_DOC: Phase 3 Quality Gates still show 'Not run'.")
fi

# =============================================================================
# SECTION 2: Code Quality (run right now)
# =============================================================================

FMT_EXIT=0
cargo fmt --check >/dev/null 2>&1 || FMT_EXIT=$?
if [ "$FMT_EXIT" -ne 0 ]; then
    FAILURES+=("CODE_QUALITY: cargo fmt --check FAILED.")
fi

CLIPPY_EXIT=0
cargo clippy -- -D warnings >/dev/null 2>&1 || CLIPPY_EXIT=$?
if [ "$CLIPPY_EXIT" -ne 0 ]; then
    FAILURES+=("CODE_QUALITY: cargo clippy FAILED.")
fi

TEST_EXIT=0
cargo test >/dev/null 2>&1 || TEST_EXIT=$?
if [ "$TEST_EXIT" -ne 0 ]; then
    FAILURES+=("CODE_QUALITY: cargo test FAILED.")
fi

IGNORE_COUNT=$(find "${PROJECT_ROOT}/src/" -name '*.rs' -type f -exec grep -l '```ignore' {} \; 2>/dev/null | wc -l)
if [ "$IGNORE_COUNT" -gt 0 ]; then
    FAILURES+=("CODE_QUALITY: Found $IGNORE_COUNT file(s) with banned \`\`\`ignore doctests.")
fi

IGNORED_TESTS=$(grep -rn '#\[ignore\]' "${PROJECT_ROOT}/src/" --include='*.rs' 2>/dev/null | wc -l)
if [ "$IGNORED_TESTS" -gt 0 ]; then
    FAILURES+=("CODE_QUALITY: Found $IGNORED_TESTS #[ignore] attribute(s) on tests.")
fi

# =============================================================================
# SECTION 3: Knowledge Recording
# =============================================================================

if [ -n "$TRANSCRIPT_PATH" ] && [ -f "$TRANSCRIPT_PATH" ]; then
    TOOL_CALLS=$(get_tool_calls "$TRANSCRIPT_PATH")

    if ! echo "$TOOL_CALLS" | grep -q "^learn$"; then
        FAILURES+=("KNOWLEDGE: 'learn' was not called.")
    fi

    if ! echo "$TOOL_CALLS" | grep -q "^save-generation-trace$"; then
        FAILURES+=("KNOWLEDGE: 'save-generation-trace' was not called. Phase 6 must record the AAR.")
    fi

    if ! echo "$TOOL_CALLS" | grep -q "^bootstrap$"; then
        FAILURES+=("KNOWLEDGE: 'bootstrap' was not called this session.")
    fi

    if ! echo "$TOOL_CALLS" | grep -q "^recall$"; then
        FAILURES+=("KNOWLEDGE: 'recall' was not called this session.")
    fi
fi

# =============================================================================
# SECTION 4: Documentation
# =============================================================================

CHANGELOG_HAS_CHANGES=false
if git diff --name-only 2>/dev/null | grep -q "CHANGELOG.md"; then
    CHANGELOG_HAS_CHANGES=true
fi
if git diff --cached --name-only 2>/dev/null | grep -q "CHANGELOG.md"; then
    CHANGELOG_HAS_CHANGES=true
fi
if [ "$CHANGELOG_HAS_CHANGES" = "false" ]; then
    FAILURES+=("CHANGELOG: CHANGELOG.md has no uncommitted git changes. Update the changelog before completing.")
fi

# =============================================================================
# VERDICT
# =============================================================================

if [ ${#FAILURES[@]} -gt 0 ] || [ ${#WARNINGS[@]} -gt 0 ]; then
    {
        echo ""
        echo "============================================"
        echo "  FINAL PIPELINE CHECKLIST"
        echo "============================================"
        echo ""

        if [ ${#FAILURES[@]} -gt 0 ]; then
            echo "FAILURES (${#FAILURES[@]} — must fix before archiving):"
            echo ""
            for failure in "${FAILURES[@]}"; do
                echo "  FAIL: $failure"
                echo ""
            done
        fi

        if [ ${#WARNINGS[@]} -gt 0 ]; then
            echo "WARNINGS (${#WARNINGS[@]} — review but non-blocking):"
            echo ""
            for warning in "${WARNINGS[@]}"; do
                echo "  WARN: $warning"
                echo ""
            done
        fi

        if [ ${#FAILURES[@]} -gt 0 ]; then
            echo "STOP BLOCKED — ${#FAILURES[@]} checklist item(s) failed."
            echo "Fix all failures before the pipeline can be archived."
            echo "============================================"
        else
            echo "All critical checks passed. ${#WARNINGS[@]} warning(s) noted."
            echo "============================================"
        fi
    } >&2

    if [ ${#FAILURES[@]} -gt 0 ]; then
        exit 2
    fi
fi

exit 0
