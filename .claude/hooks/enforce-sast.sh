#!/bin/bash
# =============================================================================
# enforce-sast.sh -- SAST and Security Gate Enforcement (Rust)
# =============================================================================
#
# Checks performed:
#   1. Semgrep with Rust security rules (if installed)
#   2. cargo audit for dependency vulnerability scanning (if installed)
#   3. cargo deny for license compliance and advisory checks (if installed)
#
# Constitution References:
#   Section 15 -- SAST Requirements
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

# --- Detect changed files ---
CHANGED_FILES=$(git diff --name-only --diff-filter=ACM HEAD 2>/dev/null || true)
UNTRACKED_FILES=$(git ls-files --others --exclude-standard 2>/dev/null || true)
ALL_FILES=$(echo -e "${CHANGED_FILES}\n${UNTRACKED_FILES}" | sort -u | grep -v '^$' || true)

CHANGED_RS_FILES=$(echo "$ALL_FILES" | grep '\.rs$' || true)

FILTERED_RS_FILES=""
while IFS= read -r file; do
    [ -z "$file" ] && continue
    if [[ "$file" == target/* ]]; then
        continue
    fi
    if [[ "$file" == *.generated.rs ]]; then
        continue
    fi
    if [ -f "$file" ]; then
        FILTERED_RS_FILES="${FILTERED_RS_FILES}${file}"$'\n'
    fi
done <<< "$CHANGED_RS_FILES"

FILTERED_RS_FILES=$(echo "$FILTERED_RS_FILES" | grep -v '^$' || true)

HAS_CARGO_CHANGES=false
if echo "$ALL_FILES" | grep -qE '(Cargo\.toml|Cargo\.lock)'; then
    HAS_CARGO_CHANGES=true
fi

if [ -z "$FILTERED_RS_FILES" ] && [ "$HAS_CARGO_CHANGES" = "false" ]; then
    exit 0
fi

CRITICAL_VIOLATIONS=()
WARNINGS=()

# =============================================================================
# CHECK 1: Semgrep
# =============================================================================
if [ -n "$FILTERED_RS_FILES" ]; then
    if command -v semgrep &>/dev/null; then
        SEMGREP_CONFIG=""
        if [ -f ".semgrep.yml" ]; then
            SEMGREP_CONFIG=".semgrep.yml"
        elif [ -f ".semgrep.yaml" ]; then
            SEMGREP_CONFIG=".semgrep.yaml"
        fi

        SEMGREP_FILES=()
        while IFS= read -r file; do
            [ -n "$file" ] && SEMGREP_FILES+=("$file")
        done <<< "$FILTERED_RS_FILES"

        if [ ${#SEMGREP_FILES[@]} -gt 0 ]; then
            SEMGREP_OUTPUT=""
            SEMGREP_EXIT=0

            if [ -n "$SEMGREP_CONFIG" ]; then
                SEMGREP_OUTPUT=$(semgrep --config "$SEMGREP_CONFIG" --json --quiet "${SEMGREP_FILES[@]}" 2>/dev/null) || SEMGREP_EXIT=$?
            else
                SEMGREP_OUTPUT=$(semgrep --config "auto" --json --quiet "${SEMGREP_FILES[@]}" 2>/dev/null) || SEMGREP_EXIT=$?
            fi

            if [ -n "$SEMGREP_OUTPUT" ]; then
                CRITICAL_COUNT=$(echo "$SEMGREP_OUTPUT" | jq '[.results[]? | select(.extra.severity == "ERROR")] | length' 2>/dev/null || echo "0")
                WARNING_COUNT=$(echo "$SEMGREP_OUTPUT" | jq '[.results[]? | select(.extra.severity == "WARNING")] | length' 2>/dev/null || echo "0")

                if [ "$CRITICAL_COUNT" -gt 0 ] 2>/dev/null; then
                    CRITICAL_DETAILS=$(echo "$SEMGREP_OUTPUT" | jq -r '.results[] | select(.extra.severity == "ERROR") | "    \(.path):\(.start.line) [\(.check_id)] \(.extra.message)"' 2>/dev/null || echo "    (details unavailable)")
                    CRITICAL_VIOLATIONS+=("SEMGREP: $CRITICAL_COUNT critical finding(s):
$CRITICAL_DETAILS")
                fi

                if [ "$WARNING_COUNT" -gt 0 ] 2>/dev/null; then
                    WARNING_DETAILS=$(echo "$SEMGREP_OUTPUT" | jq -r '.results[] | select(.extra.severity == "WARNING") | "    \(.path):\(.start.line) [\(.check_id)] \(.extra.message)"' 2>/dev/null || echo "    (details unavailable)")
                    WARNINGS+=("SEMGREP: $WARNING_COUNT warning(s):
$WARNING_DETAILS")
                fi
            fi
        fi
    else
        WARNINGS+=("SEMGREP: Not installed. Install with 'pip install semgrep' for Rust security scanning.")
    fi
fi

# =============================================================================
# CHECK 2: cargo audit
# =============================================================================
if [ "$HAS_CARGO_CHANGES" = "true" ]; then
    if command -v cargo-audit &>/dev/null; then
        AUDIT_OUTPUT=""
        AUDIT_EXIT=0
        AUDIT_OUTPUT=$(cargo audit --json 2>/dev/null) || AUDIT_EXIT=$?

        if [ "$AUDIT_EXIT" -ne 0 ] && [ -n "$AUDIT_OUTPUT" ]; then
            VULN_FOUND=$(echo "$AUDIT_OUTPUT" | jq -r '.vulnerabilities.found // false' 2>/dev/null || echo "false")

            if [ "$VULN_FOUND" = "true" ]; then
                VULN_COUNT=$(echo "$AUDIT_OUTPUT" | jq '.vulnerabilities.count // 0' 2>/dev/null || echo "0")
                VULN_DETAILS=$(echo "$AUDIT_OUTPUT" | jq -r '.vulnerabilities.list[]? | "    \(.advisory.id): \(.advisory.title) (package: \(.package.name) \(.package.version))"' 2>/dev/null || echo "    (details unavailable)")

                CRITICAL_VULN=$(echo "$AUDIT_OUTPUT" | jq '[.vulnerabilities.list[]? | select(.advisory.cvss? // "" | test("^(9|10)")) ] | length' 2>/dev/null || echo "0")

                if [ "$CRITICAL_VULN" -gt 0 ] 2>/dev/null; then
                    CRITICAL_VIOLATIONS+=("CARGO_AUDIT: $VULN_COUNT vulnerability/ies found ($CRITICAL_VULN critical/high):
$VULN_DETAILS")
                else
                    WARNINGS+=("CARGO_AUDIT: $VULN_COUNT vulnerability/ies found (medium/low severity):
$VULN_DETAILS")
                fi
            fi
        fi
    else
        WARNINGS+=("CARGO_AUDIT: Not installed. Install with 'cargo install cargo-audit' for dependency vulnerability scanning.")
    fi
fi

# =============================================================================
# CHECK 3: cargo deny
# =============================================================================
if [ "$HAS_CARGO_CHANGES" = "true" ]; then
    if command -v cargo-deny &>/dev/null; then
        if [ -f "deny.toml" ]; then
            DENY_LICENSE_OUTPUT=""
            DENY_LICENSE_EXIT=0
            DENY_LICENSE_OUTPUT=$(cargo deny check licenses 2>&1) || DENY_LICENSE_EXIT=$?

            if [ "$DENY_LICENSE_EXIT" -ne 0 ]; then
                CRITICAL_VIOLATIONS+=("CARGO_DENY (licenses): License compliance violations found:
$(echo "$DENY_LICENSE_OUTPUT" | head -20)")
            fi

            DENY_ADVISORY_OUTPUT=""
            DENY_ADVISORY_EXIT=0
            DENY_ADVISORY_OUTPUT=$(cargo deny check advisories 2>&1) || DENY_ADVISORY_EXIT=$?

            if [ "$DENY_ADVISORY_EXIT" -ne 0 ]; then
                CRITICAL_VIOLATIONS+=("CARGO_DENY (advisories): Security advisory violations found:
$(echo "$DENY_ADVISORY_OUTPUT" | head -20)")
            fi

            DENY_BAN_OUTPUT=""
            DENY_BAN_EXIT=0
            DENY_BAN_OUTPUT=$(cargo deny check bans 2>&1) || DENY_BAN_EXIT=$?

            if [ "$DENY_BAN_EXIT" -ne 0 ]; then
                WARNINGS+=("CARGO_DENY (bans): Duplicate or banned dependency warnings:
$(echo "$DENY_BAN_OUTPUT" | head -20)")
            fi
        else
            WARNINGS+=("CARGO_DENY: deny.toml not found. Create deny.toml for license and advisory enforcement.")
        fi
    else
        WARNINGS+=("CARGO_DENY: Not installed. Install with 'cargo install cargo-deny' for license compliance.")
    fi
fi

# =============================================================================
# VERDICT
# =============================================================================

if [ ${#WARNINGS[@]} -gt 0 ]; then
    {
        echo ""
        echo "SAST WARNINGS (non-blocking):"
        echo ""
        for warning in "${WARNINGS[@]}"; do
            echo "  WARNING: $warning"
            echo ""
        done
    } >&2
fi

if [ ${#CRITICAL_VIOLATIONS[@]} -gt 0 ]; then
    {
        echo ""
        echo "STOP BLOCKED -- SAST security gates not met:"
        echo ""
        for violation in "${CRITICAL_VIOLATIONS[@]}"; do
            echo "  VIOLATION: $violation"
            echo ""
        done
        echo "Fix all critical/high severity findings before stopping."
        echo ""
        echo "Quick fixes:"
        echo "  - Run 'semgrep --config .semgrep.yml .' to see semgrep findings"
        echo "  - Run 'cargo audit' to see dependency vulnerabilities"
        echo "  - Run 'cargo deny check' to see license/advisory violations"
        echo "  - Update vulnerable dependencies with 'cargo update'"
    } >&2
    exit 2
fi

exit 0
