#!/usr/bin/env bash
# ScorchKit's canonical quality gate. Cargo commands run sequentially.

set -uo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT_DIR" || exit 2

# shellcheck source=bin/gate-state.sh
. "$ROOT_DIR/bin/gate-state.sh" || exit 2

MODE="full"
case "${1:-}" in
    "") MODE="full" ;;
    --fast | fast) MODE="fast" ;;
    --diff | diff) MODE="diff" ;;
    --full | full) MODE="full" ;;
    --focused-repair | focused-repair) MODE="focused-repair" ;;
    *) echo "usage: bin/gate.sh [--fast|--diff|--full|--focused-repair]" >&2; exit 2 ;;
esac
[ "${GATE_FAST:-0}" = "1" ] && MODE="fast"

FOCUSED_EVIDENCE_NAME="${SCORCHKIT_FOCUSED_EVIDENCE_NAME:-}"
if [ "$MODE" = "focused-repair" ] && [ -z "$FOCUSED_EVIDENCE_NAME" ]; then
    shopt -s nullglob
    focused_active_specs=(docs/planning/pipeline/active/*.spec.md)
    shopt -u nullglob
    if [ "${#focused_active_specs[@]}" -eq 1 ]; then
        focused_ticket="$(awk -F ': *' '$1 == "ticket" { print $2; exit }' \
            "${focused_active_specs[0]}")"
        [[ "$focused_ticket" =~ ^TICKET-([0-9]+)$ ]] || {
            echo "focused-repair mode could not resolve the active ticket" >&2
            exit 2
        }
        FOCUSED_EVIDENCE_NAME="scorchkit-mutants-focused-ticket-${BASH_REMATCH[1]}"
    elif [ "${#focused_active_specs[@]}" -eq 0 ]; then
        FOCUSED_EVIDENCE_NAME="$(find "$SCORCHKIT_GIT_DIR" -maxdepth 1 -type d \
            -name 'scorchkit-mutants-focused-ticket-*' -print 2>/dev/null \
            | LC_ALL=C sort | tail -1)"
        FOCUSED_EVIDENCE_NAME="${FOCUSED_EVIDENCE_NAME##*/}"
        [ -n "$FOCUSED_EVIDENCE_NAME" ] || {
            echo "focused-repair mode found no sealed evidence" >&2
            exit 2
        }
    else
        echo "focused-repair mode requires exactly zero or one active pipeline" >&2
        exit 2
    fi
fi
FOCUSED_EVIDENCE_DIR="$SCORCHKIT_GIT_DIR/$FOCUSED_EVIDENCE_NAME"
FOCUSED_EVIDENCE_DIGEST=""

# The workspace lives on a noexec volume on the development Mac. Respect an
# explicit operator choice and otherwise move only Cargo's generated output.
case "$ROOT_DIR" in
    /Volumes/*)
        export CARGO_TARGET_DIR="${CARGO_TARGET_DIR:-/tmp/scorchkit-target-${UID}}"
        ;;
esac

CPU_TOTAL="$(sysctl -n hw.ncpu 2>/dev/null || getconf _NPROCESSORS_ONLN 2>/dev/null || echo 2)"
[[ "$CPU_TOTAL" =~ ^[1-9][0-9]*$ ]] || CPU_TOTAL=2
DEFAULT_CPU_BUDGET=$((CPU_TOTAL / 2))
[ "$DEFAULT_CPU_BUDGET" -lt 1 ] && DEFAULT_CPU_BUDGET=1
GATE_CPU_BUDGET="${GATE_CPU_BUDGET:-$DEFAULT_CPU_BUDGET}"
[[ "$GATE_CPU_BUDGET" =~ ^[1-9][0-9]*$ ]] || GATE_CPU_BUDGET="$DEFAULT_CPU_BUDGET"
export CARGO_BUILD_JOBS="${CARGO_BUILD_JOBS:-$GATE_CPU_BUDGET}"
export RUST_TEST_THREADS="${RUST_TEST_THREADS:-$GATE_CPU_BUDGET}"
export NEXTEST_TEST_THREADS="${NEXTEST_TEST_THREADS:-$GATE_CPU_BUDGET}"

COVERAGE_FLOOR=62
COVERAGE_MIN="${SCORCHKIT_COVERAGE_MIN:-$COVERAGE_FLOOR}"
if ! [[ "$COVERAGE_MIN" =~ ^[0-9]+([.][0-9]+)?$ ]]; then
    echo "SCORCHKIT_COVERAGE_MIN must be numeric" >&2
    exit 2
fi
if awk -v current="$COVERAGE_MIN" -v floor="$COVERAGE_FLOOR" \
    'BEGIN { exit !(current + 0 < floor + 0) }'; then
    echo "coverage override below $COVERAGE_FLOOR%; clamped to the baked floor" >&2
    COVERAGE_MIN="$COVERAGE_FLOOR"
fi

echo "cpu budget: $GATE_CPU_BUDGET/$CPU_TOTAL cores"

PASS=0
FAIL=0
SKIP=0
RESULTS=()

run_gate() {
    local label="$1"
    shift
    echo
    echo "==> $label"
    if "$@"; then
        RESULTS+=("PASS  $label")
        PASS=$((PASS + 1))
    else
        RESULTS+=("FAIL  $label")
        FAIL=$((FAIL + 1))
    fi
}

skip_gate() {
    local label="$1"
    local reason="$2"
    RESULTS+=("SKIP  $label ($reason)")
    SKIP=$((SKIP + 1))
}

need() {
    local command_name="$1"
    local install_hint="$2"
    if command -v "$command_name" >/dev/null 2>&1; then
        return 0
    fi
    echo "missing $command_name; install with: $install_hint" >&2
    return 1
}

clippy_matrix() {
    local line states count=0
    local -a flags
    states="$(bash bin/feature-states.sh "$ROOT_DIR")" || {
        echo "feature-state derivation failed" >&2
        return 1
    }
    grep -qx -- '--all-features' <<< "$states" || {
        echo "feature-bearing manifest produced no all-features Clippy state" >&2
        return 1
    }
    while IFS= read -r line; do
        if [ "$line" = '<default>' ]; then
            echo "clippy feature state: $line"
            cargo clippy --workspace --all-targets -- -D warnings </dev/null || return 1
        else
            read -r -a flags <<< "$line"
            echo "clippy feature state: $line"
            cargo clippy --workspace --all-targets "${flags[@]}" -- -D warnings </dev/null \
                || return 1
        fi
        count=$((count + 1))
    done <<< "$states"
    [ "$count" -gt 1 ] || { echo "feature-state matrix is unexpectedly empty" >&2; return 1; }
}

all_tests_gate() {
    cargo test --workspace --all-features || return 1
    bash bin/console.sh check
}

doc_gate() {
    local output
    output="$(RUSTDOCFLAGS="-D warnings" cargo doc --workspace --all-features --no-deps 2>&1)"
    local status=$?
    printf '%s\n' "$output"
    [ "$status" -eq 0 ] || return "$status"
    if grep -q '^warning:' <<< "$output"; then
        echo "cargo doc emitted a warning that did not affect its exit code" >&2
        return 1
    fi
}

audit_gate() {
    need cargo-audit "cargo install cargo-audit --locked" || return 1
    cargo audit || return 1
    cargo audit --no-fetch --file apps/scorchkit-console/Cargo.lock
}

deny_gate() {
    need cargo-deny "cargo install cargo-deny --locked" || return 1
    cargo deny check
}

machete_gate() {
    need cargo-machete "cargo install cargo-machete --locked" || return 1
    cargo machete || return 1
    cargo machete apps/scorchkit-console
}

gitleaks_gate() {
    need gitleaks "brew install gitleaks" || return 1
    gitleaks dir . --no-banner --redact=100
}

shellcheck_gate() {
    need shellcheck "brew install shellcheck" || return 1
    shellcheck -x bin/*.sh .githooks/* || return 1
    bash bin/feature-states.sh --selftest || return 1
    bash bin/mutants.sh --selftest || return 1
    bash bin/focused-mutation-evidence.sh --selftest || return 1
    bash bin/sealed-mutation-baseline.sh --selftest || return 1
    bash bin/release.sh --selftest || return 1
    bash bin/pipeline.sh selftest || return 1
    bash .githooks/pre-commit --selftest || return 1
    GATE_SELFTEST=1 bash bin/gate.sh
}

no_suppressions_gate() {
    local hits ignored blanket
    # The awk program is literal; awk expands its own fields.
    # shellcheck disable=SC2016
    hits="$(find src crates apps/scorchkit-console/src apps/scorchkit-console/tests \
        -type f -name '*.rs' -print0 | xargs -0 awk '
        FNR == 1 { justified = 0 }
        /^[[:space:]]*\/\// {
            if ($0 ~ /JUSTIFICATION:/) justified = 1
            next
        }
        /#!?\[(allow|expect)\(/ {
            if ($0 !~ /JUSTIFICATION:/ && !justified) {
                printf "%s:%d: %s\n", FILENAME, FNR, $0
            }
            justified = 0
            next
        }
        /^[[:space:]]*#\[/ { next }
        { justified = 0 }
    ')"
    if [ -n "$hits" ]; then
        echo "lint suppressions without an adjacent JUSTIFICATION comment:" >&2
        printf '%s\n' "$hits" >&2
        return 1
    fi
    # Attribute checks are anchored so prose that merely documents `#[ignore]`
    # does not become a false positive.
    # shellcheck disable=SC2016
    ignored="$(find src crates tests examples apps/scorchkit-console/src \
        apps/scorchkit-console/tests -type f -name '*.rs' -print0 | xargs -0 awk '
        /^[[:space:]]*#\[ignore([[:space:]]|\])/ &&
        $0 !~ /^[[:space:]]*#\[ignore[[:space:]]*=[[:space:]]*"[^"[:space:]][^"]*"\][[:space:]]*$/ {
            printf "%s:%d: %s\n", FILENAME, FNR, $0
        }
    ')"
    if [ -n "$ignored" ]; then
        echo "ignored tests require a nonempty inline reason:" >&2
        printf '%s\n' "$ignored" >&2
        return 1
    fi
    # shellcheck disable=SC2016
    blanket="$(find src crates tests examples apps/scorchkit-console/src \
        apps/scorchkit-console/tests -type f -name '*.rs' -print0 | xargs -0 awk '
        /^[[:space:]]*#!?\[(allow|expect)\([^]]*(clippy::(all|cargo|nursery|pedantic)|warnings|unused|dead_code)([[:space:],)]|$)/ {
            printf "%s:%d: %s\n", FILENAME, FNR, $0
        }
    ')"
    if [ -n "$blanket" ]; then
        echo "blanket lint-group suppressions are banned:" >&2
        printf '%s\n' "$blanket" >&2
        return 1
    fi
}

source_bans_gate() {
    local unsafe_hits exit_hits transmute_hits
    unsafe_hits="$(find src crates apps/scorchkit-console/src apps/scorchkit-console/tests \
        -type f -name '*.rs' -print0 | xargs -0 grep -nE '(^|[^[:alnum:]_])unsafe[[:space:]]*\{' 2>/dev/null || true)"
    exit_hits="$(find src crates apps/scorchkit-console/src apps/scorchkit-console/tests \
        -type f -name '*.rs' ! -name 'main.rs' -print0 | xargs -0 grep -nE '(std::)?process::exit[[:space:]]*\(' 2>/dev/null || true)"
    transmute_hits="$(find src crates apps/scorchkit-console/src apps/scorchkit-console/tests \
        -type f -name '*.rs' -print0 | xargs -0 grep -nE '(^|[^[:alnum:]_])(std::)?(mem::)?transmute([_:]|[[:space:]]*\()' 2>/dev/null || true)"
    if [ -n "$unsafe_hits$exit_hits$transmute_hits" ]; then
        [ -z "$unsafe_hits" ] || { echo "unsafe blocks are banned:" >&2; printf '%s\n' "$unsafe_hits" >&2; }
        [ -z "$exit_hits" ] || { echo "library process exits are banned:" >&2; printf '%s\n' "$exit_hits" >&2; }
        [ -z "$transmute_hits" ] || { echo "transmute is banned:" >&2; printf '%s\n' "$transmute_hits" >&2; }
        return 1
    fi
}

todo_gate() {
    local hits
    hits="$(
        find src crates docs -type f \( -name '*.rs' -o -name '*.md' \) \
            ! -path 'docs/planning/*' -print0 \
            | xargs -0 grep -nE '(^|[[:space:]])(TODO|FIXME|XXX)([[:space:]]|:|\()' 2>/dev/null \
            || true
    )"
    if [ -n "$hits" ]; then
        echo "actionable TODO/FIXME/XXX markers outside planning documents:" >&2
        printf '%s\n' "$hits" >&2
        return 1
    fi
}

metadata_format_gate() {
    local toml_file
    need cargo-sort "cargo install cargo-sort --locked" || return 1
    need taplo "cargo install taplo-cli --locked" || return 1
    need typos "cargo install typos-cli --locked" || return 1
    cargo sort --check --no-format || return 1
    cargo sort --check --no-format apps/scorchkit-console || return 1
    while IFS= read -r toml_file; do
        [ -f "$toml_file" ] || continue
        taplo fmt --check "$toml_file" || return 1
    done < <(git ls-files --cached --others --exclude-standard -- '*.toml')
    typos || return 1
    bash bin/codex-plugin-contract.sh --selftest
}

semgrep_gate() {
    need semgrep "pipx install semgrep" || return 1
    semgrep --config .semgrep.yml --error --quiet src crates tests apps/scorchkit-console
}

coverage_gate() {
    need cargo-llvm-cov "cargo install cargo-llvm-cov --locked" || return 1
    cargo llvm-cov --workspace --all-features \
        --ignore-filename-regex '(^|/)main\.rs$' \
        --fail-under-lines "$COVERAGE_MIN"
}

focused_repair_scope_gate() {
    local evidence_roadmap evidence_ticket ticket_doc
    local -a active_specs closed_tickets
    [ -f "$FOCUSED_EVIDENCE_DIR/summary.json" ] || {
        echo "focused-repair evidence summary is missing" >&2
        return 1
    }
    evidence_ticket="$(jq -r '.ticket // empty' "$FOCUSED_EVIDENCE_DIR/summary.json")"
    evidence_roadmap="$(jq -r '.roadmap_item // empty' "$FOCUSED_EVIDENCE_DIR/summary.json")"
    [[ "$evidence_ticket" =~ ^TICKET-[0-9]+$ ]] \
        && [[ "$evidence_roadmap" =~ ^SK-[0-9]+$ ]] || {
        echo "focused-repair evidence has an invalid ticket or roadmap item" >&2
        return 1
    }
    shopt -s nullglob
    active_specs=(docs/planning/pipeline/active/*.spec.md)
    shopt -u nullglob
    if [ "${#active_specs[@]}" -eq 1 ]; then
        if ! grep -Fqx "ticket: $evidence_ticket" "${active_specs[0]}" \
            || ! grep -Fqx 'focused_repair: approved' "${active_specs[0]}" \
            || ! grep -Fqx "focused_evidence: $FOCUSED_EVIDENCE_NAME" \
                "${active_specs[0]}"; then
            echo "focused-repair mode is not recorded for the active ticket" >&2
            return 1
        fi
        ticket_doc="$(awk -F ': *' '$1 == "ticket_doc" { print $2; exit }' \
            "${active_specs[0]}")"
        if [ ! -f "$ticket_doc" ] \
            || ! grep -Fqx 'focused_repair: approved' "$ticket_doc"; then
            echo "focused-repair approval is missing from the active ticket" >&2
            return 1
        fi
    elif [ "${#active_specs[@]}" -eq 0 ]; then
        shopt -s nullglob
        closed_tickets=(docs/planning/tickets/closed/"$evidence_ticket"-*.md)
        shopt -u nullglob
        if [ "${#closed_tickets[@]}" -ne 1 ] \
            || ! grep -Fqx 'focused_repair: approved' "${closed_tickets[0]}"; then
            echo "focused-repair delivery requires its approved archived ticket" >&2
            return 1
        fi
    else
        echo "focused-repair delivery requires exactly zero or one active pipeline" >&2
        return 1
    fi
    jq -e '.owner_approval | type == "string" and length > 0' \
        "$FOCUSED_EVIDENCE_DIR/summary.json" >/dev/null || {
        echo "focused-repair evidence does not contain owner approval" >&2
        return 1
    }
}

mutation_gate() {
    case "$MODE" in
        diff) bash bin/mutants.sh --diff ;;
        full) bash bin/mutants.sh --full ;;
        focused-repair)
            scorchkit_verify_focused_evidence "$FOCUSED_EVIDENCE_DIR" || return 1
            FOCUSED_EVIDENCE_DIGEST="$(scorchkit_focused_evidence_digest \
                "$FOCUSED_EVIDENCE_DIR")" || return 1
            ;;
        *)
            echo "mutation gate received unsupported mode: $MODE" >&2
            return 1
            ;;
    esac
}

browser_e2e_gate() {
    need node "install Node.js 22 or newer" || return 1
    need chromedriver "install the ChromeDriver matching the delivery browser" || return 1
    bash bin/console.sh build || return 1
    node tests/conversation_workbench_ui.mjs browser || return 1
    node tests/rustal_console_ui.mjs browser
}

dogfood_render_gate() {
    need node "install Node.js 22 or newer" || return 1
    node tests/conversation_workbench_ui.mjs render || return 1
    node tests/rustal_console_ui.mjs render
}

built_css_gate() {
    need node "install Node.js 22 or newer" || return 1
    node tests/conversation_workbench_ui.mjs css || return 1
    node tests/rustal_console_ui.mjs css
}

database_gate() {
    if [ -z "${DATABASE_URL:-}" ]; then
        echo "DATABASE_URL is required for the delivery-tier database tests" >&2
        return 1
    fi
    cargo test --all-features --test storage --test storage_integration --test mcp_tools
}

contract_gate() {
    cargo test --all-features --test cli --test code_scan --test scan_plan --test mcp_tools
}

nextest_gate() {
    need cargo-nextest "cargo install cargo-nextest --locked" || return 1
    need jq "brew install jq (macOS) or apt-get install jq (Linux)" || return 1
    local listing empty allowlisted_empty_suites
    listing="$(cargo nextest list --workspace --all-features --message-format json 2>/dev/null)" \
        || {
        echo "nextest could not list test suites" >&2
        return 1
    }
    [ -n "$listing" ] || { echo "nextest produced an empty suite listing" >&2; return 1; }
    printf '%s' "$listing" | jq -e '."rust-suites" | length > 0' >/dev/null || {
        echo "nextest reported zero Rust suites" >&2
        return 1
    }
    empty="$(printf '%s' "$listing" \
        | jq -r '."rust-suites" | to_entries[]
            | select((.value.testcases | length) == 0) | .key' \
        | grep -v '::bin/' | LC_ALL=C sort || true)"
    # These boundary packages currently publish only types or parsing contracts. Their behavior is
    # covered by the root integration and workspace-architecture suites. Keep the list exact so a
    # newly empty package fails, and adding package-local tests forces removal of the stale entry.
    allowlisted_empty_suites="$(printf '%s\n' \
        scorchkit-cloud \
        scorchkit-infra \
        scorchkit-web \
        | LC_ALL=C sort)"
    if [ "$empty" != "$allowlisted_empty_suites" ]; then
        echo "non-binary zero-test suite inventory changed:" >&2
        echo "actual:" >&2
        printf '%s\n' "$empty" >&2
        echo "allowlisted:" >&2
        printf '%s\n' "$allowlisted_empty_suites" >&2
        return 1
    fi
    cargo nextest run --workspace --all-features
}

gate_selftest() {
    local actual expected
    actual="$(grep -oE '(run_gate|skip_gate) "gate:[0-9]+' bin/gate.sh \
        | sed -E 's/.*gate:([0-9]+)/\1/' | sort -n -u | tr '\n' ' ')"
    expected="$(seq 1 22 | tr '\n' ' ')"
    [ "$actual" = "$expected" ] || {
        echo "gate selftest failed: expected gates 1-22, saw: $actual" >&2
        return 1
    }
    grep -q 'scorchkit_write_gate_receipt' bin/gate.sh || {
        echo "gate selftest failed: delivery receipt writer is not wired" >&2
        return 1
    }
    grep -q 'allowlisted_empty_suites' bin/gate.sh || {
        echo "gate selftest failed: zero-test workspace suite inventory is not explicit" >&2
        return 1
    }
    if ! grep -q 'node tests/conversation_workbench_ui.mjs browser' bin/gate.sh \
        || ! grep -q 'node tests/conversation_workbench_ui.mjs render' bin/gate.sh \
        || ! grep -q 'node tests/conversation_workbench_ui.mjs css' bin/gate.sh \
        || ! grep -q 'node tests/rustal_console_ui.mjs browser' bin/gate.sh \
        || ! grep -q 'node tests/rustal_console_ui.mjs render' bin/gate.sh \
        || ! grep -q 'node tests/rustal_console_ui.mjs css' bin/gate.sh \
        || ! grep -q 'bash bin/console.sh check' bin/gate.sh; then
        echo "gate selftest failed: delivery UI evidence is not wired" >&2
        return 1
    fi
    if ! grep -q -- '--focused-repair' bin/gate.sh \
        || ! grep -q 'scorchkit_verify_focused_evidence' bin/gate.sh \
        || ! grep -q 'focused_repair_scope_gate' bin/gate.sh \
        || ! grep -q 'bash bin/mutants.sh --diff' bin/gate.sh \
        || ! grep -q 'bash bin/mutants.sh --full' bin/gate.sh; then
        echo "gate selftest failed: mutation modes are not wired independently" >&2
        return 1
    fi
    echo "gate selftest OK (stable gates 1-22, explicit mutation modes, and receipt writer)"
}

if [ "${GATE_SELFTEST:-0}" = "1" ]; then
    gate_selftest
    exit $?
fi

if [ "$MODE" = "focused-repair" ]; then
    focused_repair_scope_gate || exit 2
fi

run_gate "gate:1 rustfmt" cargo fmt --all -- --check
run_gate "gate:2 clippy feature matrix" clippy_matrix
run_gate "gate:3 all-feature tests" all_tests_gate
run_gate "gate:4 rustdoc" doc_gate
run_gate "gate:5 cargo-audit" audit_gate
run_gate "gate:6 cargo-deny" deny_gate
run_gate "gate:7 cargo-machete" machete_gate
run_gate "gate:8 gitleaks" gitleaks_gate
run_gate "gate:9 shellcheck" shellcheck_gate
run_gate "gate:10 justified suppressions" no_suppressions_gate
run_gate "gate:11 source bans" source_bans_gate
run_gate "gate:12 doc TODOs" todo_gate
run_gate "gate:13 TOML and spelling" metadata_format_gate
run_gate "gate:14 semgrep" semgrep_gate
STATIC_FAILURES="$FAIL"

if [ "$MODE" = "fast" ]; then
    skip_gate "gate:15 coverage" "fast mode"
    skip_gate "gate:16 mutation" "fast mode"
    skip_gate "gate:17 browser e2e" "fast mode"
    skip_gate "gate:18 website dogfood render" "fast mode"
    skip_gate "gate:19 built CSS sheets" "fast mode"
    skip_gate "gate:20 nextest strictness" "fast mode"
    skip_gate "gate:21 PostgreSQL integration" "fast mode"
    skip_gate "gate:22 CLI and MCP contracts" "fast mode"
elif [ "$STATIC_FAILURES" -gt 0 ]; then
    skip_gate "gate:15 coverage" "static prerequisite failed"
    skip_gate "gate:16 mutation (MSI >= 95%)" "static prerequisite failed"
    skip_gate "gate:17 browser e2e" "static prerequisite failed"
    skip_gate "gate:18 website dogfood render" "static prerequisite failed"
    skip_gate "gate:19 built CSS sheets" "static prerequisite failed"
    skip_gate "gate:20 nextest strictness" "static prerequisite failed"
    skip_gate "gate:21 PostgreSQL integration" "static prerequisite failed"
    skip_gate "gate:22 CLI and MCP contracts" "static prerequisite failed"
else
    run_gate "gate:15 coverage" coverage_gate
    if [ "$FAIL" -gt 0 ]; then
        skip_gate "gate:16 mutation (MSI >= 95%)" "coverage prerequisite failed"
    else
        run_gate "gate:16 mutation (MSI >= 95%)" mutation_gate
    fi
    run_gate "gate:17 browser e2e" browser_e2e_gate
    run_gate "gate:18 website dogfood render" dogfood_render_gate
    run_gate "gate:19 built CSS sheets" built_css_gate
    run_gate "gate:20 nextest strictness" nextest_gate
    run_gate "gate:21 PostgreSQL integration" database_gate
    run_gate "gate:22 CLI and MCP contracts" contract_gate
fi

echo
echo "== gate summary ($MODE) =="
for result in "${RESULTS[@]}"; do
    echo "  $result"
done
echo "  $PASS passed, $FAIL failed, $SKIP skipped"

if [ "$FAIL" -gt 0 ]; then
    echo "GATE RED — fix at source"
    exit 1
fi

echo "GATE GREEN [$MODE]"
if [ "$MODE" != "fast" ]; then
    RECEIPT_EVIDENCE_NAME=""
    RECEIPT_EVIDENCE_DIGEST=""
    if [ "$MODE" = "focused-repair" ]; then
        RECEIPT_EVIDENCE_NAME="$FOCUSED_EVIDENCE_NAME"
        RECEIPT_EVIDENCE_DIGEST="$FOCUSED_EVIDENCE_DIGEST"
    fi
    SCORCHKIT_GATE_MODE="$MODE" \
        SCORCHKIT_GATE_EVIDENCE_NAME="$RECEIPT_EVIDENCE_NAME" \
        SCORCHKIT_GATE_EVIDENCE_DIGEST="$RECEIPT_EVIDENCE_DIGEST" \
        scorchkit_write_gate_receipt || exit 1
    echo "delivery receipt: $SCORCHKIT_GATE_RECEIPT"
fi
