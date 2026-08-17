#!/usr/bin/env bash
# Validate the repository-owned ScorchKit Codex plugin and its workflow boundaries.

set -uo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
PLUGIN_DIR="${SCORCHKIT_PLUGIN_DIR:-$ROOT_DIR/plugins/scorchkit}"
EXPECTED_SKILLS=(
    plan-security-engagement
    prepare-security-engagement
    report-security-findings
    run-security-engagement
    verify-security-remediation
)
readonly EXPECTED_SKILLS
SELFTEST_TEMPORARY=""

fail() {
    echo "Codex plugin contract failed: $*" >&2
    exit 1
}

need() {
    command -v "$1" >/dev/null 2>&1 || fail "missing required command: $1"
}

require_text() {
    local file="$1"
    shift
    local expected
    for expected in "$@"; do
        grep -Fq -- "$expected" "$file" || fail "$(basename "$(dirname "$file")") lacks: $expected"
    done
}

validate_manifest() {
    local manifest="$PLUGIN_DIR/.codex-plugin/plugin.json"
    [ -f "$manifest" ] && [ ! -L "$manifest" ] || fail "plugin manifest is missing or linked"
    jq -e '
        .name == "scorchkit"
        and (.version | test("^[0-9]+\\.[0-9]+\\.[0-9]+([+-][0-9A-Za-z.-]+)?$"))
        and (.description | type == "string" and length > 20)
        and .author.name == "Ignibyte"
        and .license == "MIT"
        and .skills == "./skills/"
        and .mcpServers == "./.mcp.json"
        and (.apps | not)
        and (.hooks | not)
        and .interface.displayName == "ScorchKit"
        and .interface.developerName == "Ignibyte"
        and .interface.category == "Security"
        and .interface.capabilities == ["Interactive", "Read", "Write"]
        and (.interface.defaultPrompt | type == "array" and length > 0 and length <= 3)
        and all(.interface.defaultPrompt[]; type == "string" and length > 0 and length <= 128)
    ' "$manifest" >/dev/null || fail "plugin.json does not match the published package contract"
}

validate_mcp() {
    local config="$PLUGIN_DIR/.mcp.json"
    [ -f "$config" ] && [ ! -L "$config" ] || fail "MCP descriptor is missing or linked"
    jq -e '
        (.mcpServers | keys) == ["scorchkit"]
        and .mcpServers.scorchkit.command == "scorchkit"
        and .mcpServers.scorchkit.args == ["serve"]
        and .mcpServers.scorchkit.env_vars == ["DATABASE_URL"]
        and .mcpServers.scorchkit.tool_timeout_sec == 3600
        and (.mcpServers.scorchkit.cwd | not)
        and (.mcpServers.scorchkit.env | not)
        and (.mcpServers.scorchkit.headers | not)
    ' "$config" >/dev/null || fail ".mcp.json is not the bounded local stdio contract"
}

validate_skill_inventory() {
    local actual expected
    actual="$(find "$PLUGIN_DIR/skills" -mindepth 1 -maxdepth 1 -type d -print \
        | while IFS= read -r path; do basename "$path"; done | LC_ALL=C sort)"
    expected="$(printf '%s\n' "${EXPECTED_SKILLS[@]}" | LC_ALL=C sort)"
    [ "$actual" = "$expected" ] || fail "skill inventory differs from the five phase contract"
}

validate_skill() {
    local skill="$1" directory skill_file metadata workflow
    directory="$PLUGIN_DIR/skills/$skill"
    skill_file="$directory/SKILL.md"
    metadata="$directory/agents/openai.yaml"
    [ -f "$skill_file" ] && [ ! -L "$skill_file" ] || fail "$skill SKILL.md is missing or linked"
    [ -f "$metadata" ] && [ ! -L "$metadata" ] || fail "$skill UI metadata is missing or linked"
    awk -v expected="$skill" '
        NR == 1 && $0 != "---" { exit 1 }
        NR == 2 && $0 != "name: " expected { exit 1 }
        NR == 3 && $0 !~ /^description: "[^"].*"$/ { exit 1 }
        NR == 4 && $0 != "---" { exit 1 }
        NR == 4 { found = 1; exit }
        END { if (!found) exit 1 }
    ' "$skill_file" || fail "$skill frontmatter is not the exact name/description contract"
    grep -Fq -- "\$$skill" "$metadata" || fail "$skill default prompt does not name the skill"
    grep -Eq '^  short_description: "[^"].{23,62}"$' "$metadata" \
        || fail "$skill short description is outside the 25-64 character contract"
    # Backticks are literal command markers in the expression.
    # shellcheck disable=SC2016
    if grep -nE 'TODO|FIXME|XXX|```|(^|[[:space:]`])(bash|cargo|codex|scorchkit|zsh)[[:space:]]' \
        "$skill_file" >/dev/null; then
        fail "$skill contains a placeholder, command block, or raw command instruction"
    fi
    require_text "$skill_file" \
        "Use only ScorchKit MCP tools and resources." \
        "do not substitute another execution path" \
        "Prefer native \`structuredContent\`" \
        "trace context, never authorization"
    workflow="$(awk '/^## Workflow$/ { active = 1; next } active { print }' "$skill_file")"
    [ -n "$workflow" ] || fail "$skill has no workflow"
    case "$skill" in
        prepare-security-engagement)
            require_text "$skill_file" project_list project_show project_create target_list target_add
            require_text "$skill_file" \
                "sole authorization source" \
                "inventory, not a grant"
            # Backticks are literal MCP tool delimiters.
            # shellcheck disable=SC2016
            if grep -Eq '`(scan|scan_job_start|project_scan|auto_scan|schedule_scan)`' \
                <<< "$workflow"; then
                fail "$skill crosses into scan execution"
            fi
            ;;
        plan-security-engagement)
            require_text "$skill_file" project_show target_list list_modules check_tools \
                target_intelligence plan_scan
            require_text "$skill_file" \
                "explicit authorization" \
                "Do not infer permission"
            # Backticks are literal MCP tool delimiters.
            # shellcheck disable=SC2016
            if grep -Eq '`(scan|scan_job_start|project_scan|auto_scan|schedule_scan)`' \
                <<< "$workflow"; then
                fail "$skill crosses into planned scan execution"
            fi
            ;;
        run-security-engagement)
            require_text "$skill_file" list_modules check_tools project_show target_list project_scan \
                scan_job_start scan_job_status scan_job_cancel scan_job_resume
            require_text "$skill_file" \
                "explicit request to execute against the exact target" \
                "least-powerful profile"
            ;;
        report-security-findings)
            require_text "$skill_file" project_show project_status project_findings finding_show \
                correlate_findings analyze_findings "provider interpretation"
            if grep -Fq 'finding_update_status' <<< "$workflow"; then
                fail "$skill mutates finding state"
            fi
            ;;
        verify-security-remediation)
            require_text "$skill_file" project_show target_list project_findings finding_show \
                list_modules project_scan project_status finding_update_status \
                "modules completed successfully"
            require_text "$skill_file" \
                "explicit user direction" \
                "same registered target" \
                "Do not broaden scope or profile"
            ;;
        *)
            fail "unexpected skill: $skill"
            ;;
    esac
}

validate_plugin() {
    local skill
    need jq || return 1
    need awk || return 1
    need grep || return 1
    [ -d "$PLUGIN_DIR" ] && [ ! -L "$PLUGIN_DIR" ] || fail "plugin directory is missing or linked"
    [ ! -e "$PLUGIN_DIR/.agents/plugins/marketplace.json" ] \
        || fail "plugin package must not mutate a marketplace"
    validate_manifest || return 1
    validate_mcp || return 1
    validate_skill_inventory || return 1
    for skill in "${EXPECTED_SKILLS[@]}"; do
        validate_skill "$skill" || return 1
    done
    echo "Codex plugin contract OK (5 skills, local stdio MCP, no command workflows)"
}

must_reject() {
    local label="$1" candidate="$2"
    if SCORCHKIT_PLUGIN_DIR="$candidate" bash "$0" >/dev/null 2>&1; then
        fail "selftest accepted $label"
    fi
}

selftest() {
    local temporary case_dir report_skill
    validate_plugin || return 1
    temporary="$(mktemp -d "${TMPDIR:-/tmp}/scorchkit-plugin-contract.XXXXXX")" || return 1
    SELFTEST_TEMPORARY="$temporary"
    trap cleanup_selftest EXIT

    case_dir="$temporary/wrong-command"
    cp -R "$PLUGIN_DIR" "$case_dir"
    jq '.mcpServers.scorchkit.command = "bash"' "$case_dir/.mcp.json" \
        > "$case_dir/.mcp.json.new" || return 1
    mv "$case_dir/.mcp.json.new" "$case_dir/.mcp.json"
    must_reject "an alternate MCP command" "$case_dir" || return 1

    case_dir="$temporary/missing-skill"
    cp -R "$PLUGIN_DIR" "$case_dir"
    mv "$case_dir/skills/plan-security-engagement" "$temporary/removed-plan-skill"
    must_reject "a missing workflow skill" "$case_dir" || return 1

    case_dir="$temporary/phase-crossover"
    cp -R "$PLUGIN_DIR" "$case_dir"
    # Backticks are literal MCP tool delimiters in the negative fixture.
    # shellcheck disable=SC2016
    printf '\n6. Use `project_scan` after registering the target.\n' \
        >> "$case_dir/skills/prepare-security-engagement/SKILL.md"
    must_reject "preparation-time scan execution" "$case_dir" || return 1

    case_dir="$temporary/raw-command"
    cp -R "$PLUGIN_DIR" "$case_dir"
    # Backticks are literal command markers in the negative fixture.
    # shellcheck disable=SC2016
    printf '\nRun `scorchkit serve` yourself.\n' \
        >> "$case_dir/skills/run-security-engagement/SKILL.md"
    must_reject "a raw command workflow" "$case_dir" || return 1

    case_dir="$temporary/report-mutation"
    cp -R "$PLUGIN_DIR" "$case_dir"
    report_skill="$case_dir/skills/report-security-findings/SKILL.md"
    # Backticks are literal MCP tool delimiters in the negative fixture.
    # shellcheck disable=SC2016
    printf '\n1. Call `finding_update_status` for every reported issue.\n' >> "$report_skill"
    must_reject "report-time finding mutation" "$case_dir" || return 1

    case_dir="$temporary/missing-structured-contract"
    cp -R "$PLUGIN_DIR" "$case_dir"
    report_skill="$case_dir/skills/report-security-findings/SKILL.md"
    sed "/Prefer native \`structuredContent\`/,+1d" "$report_skill" > "$report_skill.new" \
        || return 1
    mv "$report_skill.new" "$report_skill"
    must_reject "a workflow without native structured-result guidance" "$case_dir" || return 1

    echo "Codex plugin contract selftest OK"
}

cleanup_selftest() {
    if [[ -n "$SELFTEST_TEMPORARY" \
        && "$SELFTEST_TEMPORARY" == "${TMPDIR:-/tmp}"/scorchkit-plugin-contract.* ]]; then
        rm -rf -- "$SELFTEST_TEMPORARY"
    fi
}

case "${1:-}" in
    "")
        validate_plugin
        ;;
    --selftest)
        selftest
        ;;
    *)
        echo "usage: bin/codex-plugin-contract.sh [--selftest]" >&2
        exit 2
        ;;
esac
