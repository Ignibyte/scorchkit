#!/bin/bash
# =============================================================================
# enforce-quality.sh -- Code Quality Gate Enforcement (Rust)
# =============================================================================
#
# Blocks agents from stopping when code quality gates are not met.
#
# Checks performed on Rust files changed since last commit:
#   1. Module-level doc comments (//!) in lib.rs and mod.rs files
#   2. Doc comments (///) on all pub items
#   3. cargo fmt --check passes
#   4. cargo clippy -- -D warnings passes
#   5. No banned ```ignore doctests
#   6. #[allow(...)] without JUSTIFICATION comment
#   7. No #[ignore] on tests
#   8. No crate-level broad suppressions
#
# Constitution References:
#   Section 14 -- Code Quality Standards
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

# --- Detect changed Rust files ---
CHANGED_RS_FILES=$(git diff --name-only --diff-filter=ACM HEAD -- '*.rs' 2>/dev/null || true)
UNTRACKED_RS_FILES=$(git ls-files --others --exclude-standard -- '*.rs' 2>/dev/null || true)
ALL_RS_FILES=$(echo -e "${CHANGED_RS_FILES}\n${UNTRACKED_RS_FILES}" | sort -u | grep -v '^$' || true)

if [ -z "$ALL_RS_FILES" ]; then
    exit 0
fi

# --- Filter out target directory ---
FILTERED_FILES=""
while IFS= read -r file; do
    if [[ "$file" == target/* ]]; then
        continue
    fi
    if [[ "$file" == *.generated.rs ]]; then
        continue
    fi
    if [ -f "$file" ]; then
        FILTERED_FILES="${FILTERED_FILES}${file}"$'\n'
    fi
done <<< "$ALL_RS_FILES"

FILTERED_FILES=$(echo "$FILTERED_FILES" | grep -v '^$' || true)

if [ -z "$FILTERED_FILES" ]; then
    exit 0
fi

VIOLATIONS=()

# =============================================================================
# CHECK 1: Module-level doc comments (//!) in lib.rs and mod.rs
# =============================================================================
while IFS= read -r file; do
    BASENAME=$(basename "$file")
    if [[ "$BASENAME" == "lib.rs" || "$BASENAME" == "mod.rs" ]]; then
        if ! grep -q '^//!' "$file" 2>/dev/null; then
            VIOLATIONS+=("MODULE_DOC: Missing module-level doc comment (//!) in $file")
        fi
    fi
done <<< "$FILTERED_FILES"

# =============================================================================
# CHECK 2: Doc comments (///) on pub items
# =============================================================================
while IFS= read -r file; do
    LINE_NUM=0
    PREV_LINES=()
    while IFS= read -r line; do
        LINE_NUM=$((LINE_NUM + 1))
        TRIMMED=$(echo "$line" | sed 's/^[[:space:]]*//')

        if echo "$TRIMMED" | grep -qE '^pub (fn|struct|enum|trait|type|const|static) '; then
            HAS_DOC=false
            CHECK_IDX=$((${#PREV_LINES[@]} - 1))
            while [ "$CHECK_IDX" -ge 0 ]; do
                CHECK_TRIMMED=$(echo "${PREV_LINES[$CHECK_IDX]}" | sed 's/^[[:space:]]*//')
                if echo "$CHECK_TRIMMED" | grep -q '^///'; then
                    HAS_DOC=true
                    break
                elif echo "$CHECK_TRIMMED" | grep -q '^#\['; then
                    CHECK_IDX=$((CHECK_IDX - 1))
                else
                    break
                fi
            done

            if [ "$HAS_DOC" = "false" ]; then
                ITEM_NAME=$(echo "$TRIMMED" | sed 's/pub \(fn\|struct\|enum\|trait\|type\|const\|static\) \([a-zA-Z_][a-zA-Z0-9_]*\).*/\2/')
                ITEM_KIND=$(echo "$TRIMMED" | sed 's/pub \(fn\|struct\|enum\|trait\|type\|const\|static\) .*/\1/')
                VIOLATIONS+=("DOC_COMMENT: Missing /// doc comment on pub $ITEM_KIND $ITEM_NAME at $file:$LINE_NUM")
            fi
        fi

        PREV_LINES+=("$line")
        if [ ${#PREV_LINES[@]} -gt 10 ]; then
            PREV_LINES=("${PREV_LINES[@]:1}")
        fi
    done < "$file"
done <<< "$FILTERED_FILES"

# =============================================================================
# CHECK 3: cargo fmt --check
# =============================================================================
FMT_OUTPUT=""
FMT_EXIT=0
FMT_OUTPUT=$(cargo fmt --check 2>&1) || FMT_EXIT=$?

if [ "$FMT_EXIT" -ne 0 ]; then
    VIOLATIONS+=("CARGO_FMT: Formatting violations detected. Run 'cargo fmt' to fix:
$FMT_OUTPUT")
fi

# =============================================================================
# CHECK 4: cargo clippy
# =============================================================================
CLIPPY_OUTPUT=""
CLIPPY_EXIT=0
CLIPPY_OUTPUT=$(cargo clippy -- -D warnings 2>&1) || CLIPPY_EXIT=$?

if [ "$CLIPPY_EXIT" -ne 0 ]; then
    VIOLATIONS+=("CARGO_CLIPPY: Clippy warnings detected (treated as errors):
$CLIPPY_OUTPUT")
fi

# =============================================================================
# CHECK 5: No ```ignore doctests
# =============================================================================
IGNORE_VIOLATIONS=""
IGNORE_COUNT=0
while IFS= read -r file; do
    MATCHES=$(grep -n '^ */// *```ignore' "$file" 2>/dev/null || true)
    if [ -n "$MATCHES" ]; then
        while IFS= read -r match; do
            IGNORE_COUNT=$((IGNORE_COUNT + 1))
            LINE_NO=$(echo "$match" | cut -d: -f1)
            IGNORE_VIOLATIONS="${IGNORE_VIOLATIONS}    - ${file}:${LINE_NO}\n"
        done <<< "$MATCHES"
    fi
done < <(find src/ -name '*.rs' -type f 2>/dev/null)

if [ "$IGNORE_COUNT" -gt 0 ]; then
    VIOLATIONS+=("DOCTEST_IGNORE: Found $IGNORE_COUNT banned \`\`\`ignore doctest(s).
$(echo -e "$IGNORE_VIOLATIONS")
  Fix: Change to \`\`\`no_run or make the example fully runnable.")
fi

# =============================================================================
# CHECK 6: No #[allow(...)] without JUSTIFICATION
# =============================================================================
ALLOW_VIOLATIONS=""
ALLOW_COUNT=0
while IFS= read -r file; do
    [ -z "$file" ] && continue

    LINE_NUM=0
    IN_TEST_MODULE=false
    while IFS= read -r line; do
        LINE_NUM=$((LINE_NUM + 1))
        TRIMMED=$(echo "$line" | sed 's/^[[:space:]]*//')

        if echo "$TRIMMED" | grep -q '^#\[cfg(test)\]'; then
            IN_TEST_MODULE=true
        fi

        if [ "$IN_TEST_MODULE" = "true" ]; then
            continue
        fi

        if echo "$TRIMMED" | grep -qE '^#\[allow\('; then
            if [ "$LINE_NUM" -gt 1 ]; then
                PREV_LINE=$(sed -n "$((LINE_NUM - 1))p" "$file" 2>/dev/null | sed 's/^[[:space:]]*//')
                if ! echo "$PREV_LINE" | grep -qi '// JUSTIFICATION:'; then
                    ALLOW_COUNT=$((ALLOW_COUNT + 1))
                    ALLOW_VIOLATIONS="${ALLOW_VIOLATIONS}    - ${file}:${LINE_NUM}: ${TRIMMED}\n"
                fi
            else
                ALLOW_COUNT=$((ALLOW_COUNT + 1))
                ALLOW_VIOLATIONS="${ALLOW_VIOLATIONS}    - ${file}:${LINE_NUM}: ${TRIMMED}\n"
            fi
        fi
    done < "$file"
done <<< "$FILTERED_FILES"

if [ "$ALLOW_COUNT" -gt 0 ]; then
    VIOLATIONS+=("ALLOW_WORKAROUND: Found $ALLOW_COUNT #[allow(...)] attribute(s) without justification.
$(echo -e "$ALLOW_VIOLATIONS")
  Every #[allow(...)] MUST have a '// JUSTIFICATION: <reason>' comment on the line above it.")
fi

# =============================================================================
# CHECK 7: No #[ignore] on test functions
# =============================================================================
IGNORED_TESTS=""
IGNORED_TEST_COUNT=0
while IFS= read -r file; do
    MATCHES=$(grep -n '#\[ignore\]' "$file" 2>/dev/null || true)
    if [ -n "$MATCHES" ]; then
        while IFS= read -r match; do
            IGNORED_TEST_COUNT=$((IGNORED_TEST_COUNT + 1))
            LINE_NO=$(echo "$match" | cut -d: -f1)
            IGNORED_TESTS="${IGNORED_TESTS}    - ${file}:${LINE_NO}\n"
        done <<< "$MATCHES"
    fi
done < <(find src/ -name '*.rs' -type f 2>/dev/null)

if [ "$IGNORED_TEST_COUNT" -gt 0 ]; then
    VIOLATIONS+=("IGNORED_TEST: Found $IGNORED_TEST_COUNT #[ignore] attribute(s) on test functions.
$(echo -e "$IGNORED_TESTS")
  Fix: Remove #[ignore] and make the test pass, or delete the test.")
fi

# =============================================================================
# CHECK 8: No crate-level broad suppressions
# =============================================================================
CRATE_ALLOW_COUNT=0
CRATE_ALLOW_VIOLATIONS=""
while IFS= read -r file; do
    [ -z "$file" ] && continue
    MATCHES=$(grep -n '^#!\[allow(' "$file" 2>/dev/null || true)
    if [ -n "$MATCHES" ]; then
        while IFS= read -r match; do
            LINE_NO=$(echo "$match" | cut -d: -f1)
            LINE_CONTENT=$(echo "$match" | cut -d: -f2-)
            if echo "$file" | grep -q '/tests/'; then
                continue
            fi
            if echo "$LINE_CONTENT" | grep -qE 'allow\((unused|dead_code|warnings)\)'; then
                CRATE_ALLOW_COUNT=$((CRATE_ALLOW_COUNT + 1))
                CRATE_ALLOW_VIOLATIONS="${CRATE_ALLOW_VIOLATIONS}    - ${file}:${LINE_NO}: ${LINE_CONTENT}\n"
            fi
        done <<< "$MATCHES"
    fi
done <<< "$FILTERED_FILES"

if [ "$CRATE_ALLOW_COUNT" -gt 0 ]; then
    VIOLATIONS+=("BROAD_SUPPRESSION: Found $CRATE_ALLOW_COUNT crate-level #![allow(...)] that suppress entire warning categories.
$(echo -e "$CRATE_ALLOW_VIOLATIONS")
  Fix the underlying issues instead of suppressing the warnings.")
fi

# =============================================================================
# VERDICT
# =============================================================================
if [ ${#VIOLATIONS[@]} -gt 0 ]; then
    {
        echo ""
        echo "STOP BLOCKED -- Code quality gates not met:"
        echo ""
        for violation in "${VIOLATIONS[@]}"; do
            echo "  VIOLATION: $violation"
            echo ""
        done
        echo "Fix all violations before stopping. Constitution Section 14 is binding."
        echo ""
        echo "Quick fixes:"
        echo "  - Run 'cargo fmt' to auto-fix formatting"
        echo "  - Run 'cargo clippy -- -D warnings' to see lint warnings"
        echo "  - Add '//!' module doc comment at the top of lib.rs and mod.rs files"
        echo "  - Add '/// Description' doc comment before every pub item declaration"
        echo "  - Add '// JUSTIFICATION: <reason>' above any #[allow(...)] in production code"
        echo "  - Remove #[ignore] from tests — make them pass or delete them"
    } >&2
    exit 2
fi

exit 0
