#!/usr/bin/env bash
# Verify a completed green DIFF/FULL mutation baseline without rerunning cargo-mutants.

set -uo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT_DIR="${ROOT_DIR:-$(cd "$SCRIPT_DIR/.." && pwd)}"
EVIDENCE_FILES=(
    summary.json
    initial/outcomes.json
    initial/mutants.json
    initial/caught.txt
    initial/missed.txt
    initial/timeout.txt
    initial/unviable.txt
)
readonly EVIDENCE_FILES

usage() {
    printf '%s\n' \
        'usage: bin/sealed-mutation-baseline.sh COMMAND [ARGS]' \
        '' \
        '  --verify EVIDENCE_DIR' \
        '  --digest EVIDENCE_DIR' \
        '  --selftest'
}

need_tool() {
    local tool="$1"
    command -v "$tool" >/dev/null 2>&1 || {
        echo "sealed mutation baseline requires $tool" >&2
        return 1
    }
}

evidence_files_exist() {
    local evidence="$1" relative
    [ -d "$evidence" ] && [ ! -L "$evidence" ] || {
        echo "sealed mutation evidence directory is missing: $evidence" >&2
        return 1
    }
    for relative in "${EVIDENCE_FILES[@]}"; do
        if [ ! -f "$evidence/$relative" ] || [ -L "$evidence/$relative" ]; then
            echo "sealed mutation evidence file is missing or is a symlink: $relative" >&2
            return 1
        fi
    done
}

evidence_digest() {
    local evidence="$1" digest manifest relative result
    need_tool mktemp || return 1
    need_tool shasum || return 1
    evidence_files_exist "$evidence" || return 1
    manifest="$(mktemp "${TMPDIR:-/tmp}/scorchkit-sealed-evidence.XXXXXX")" || return 1
    : > "$manifest"
    for relative in "${EVIDENCE_FILES[@]}"; do
        digest="$(shasum -a 256 < "$evidence/$relative" | awk '{print $1}')"
        [[ "$digest" =~ ^[0-9a-f]{64}$ ]] || {
            rm -f "$manifest"
            echo "could not hash sealed mutation evidence: $relative" >&2
            return 1
        }
        printf 'PATH\0%s\0FILE\0%s\0' "$relative" "$digest" >> "$manifest"
    done
    result="$(shasum -a 256 < "$manifest" | awk '{print $1}')"
    rm -f "$manifest"
    [[ "$result" =~ ^[0-9a-f]{64}$ ]] || return 1
    printf '%s\n' "$result"
}

compare_outcome_names() {
    local outcomes="$1" outcome="$2" names="$3" actual expected
    actual="$(mktemp "${TMPDIR:-/tmp}/scorchkit-sealed-actual.XXXXXX")" || return 1
    expected="$(mktemp "${TMPDIR:-/tmp}/scorchkit-sealed-expected.XXXXXX")" || {
        rm -f "$actual"
        return 1
    }
    jq -r --arg outcome "$outcome" \
        '.outcomes[] | select(.summary == $outcome) | .scenario.Mutant.name' \
        "$outcomes" | LC_ALL=C sort > "$actual" || {
        rm -f "$actual" "$expected"
        return 1
    }
    LC_ALL=C sort "$names" > "$expected" || {
        rm -f "$actual" "$expected"
        return 1
    }
    if ! cmp -s "$actual" "$expected"; then
        rm -f "$actual" "$expected"
        echo "sealed mutation name list does not match outcomes: $names" >&2
        return 1
    fi
    rm -f "$actual" "$expected"
}

mutation_input_hash() {
    bash "$SCRIPT_DIR/focused-mutation-evidence.sh" --input-hash "$ROOT_DIR"
}

verify_evidence() {
    local evidence="$1" summary outcomes mutants
    local selected caught missed timeout unviable viable score required
    local actual_files actual_functions baseline_count current_input inventory outcome_inventory
    local reported_selected reported_caught reported_missed reported_timeout reported_unviable

    need_tool cmp || return 1
    need_tool jq || return 1
    evidence_files_exist "$evidence" || return 1
    summary="$evidence/summary.json"
    outcomes="$evidence/initial/outcomes.json"
    mutants="$evidence/initial/mutants.json"

    jq -e '
        def nni: type == "number" and . >= 0 and . == floor;
        (.ticket | test("^TICKET-[0-9]+$"))
        and (.roadmap_item | test("^SK-[0-9]+$"))
        and .mode == "sealed_green_diff"
        and .completed == true
        and (.date | type == "string" and test("^[0-9]{4}-[0-9]{2}-[0-9]{2}$"))
        and (.cargo_mutants_version | type == "string" and length > 0)
        and (.owner_approval | type == "string" and length > 0)
        and (.source_mode == "diff" or .source_mode == "full")
        and .full_repository_mutation == "deferred_by_repository_owner"
        and (.mutation_input_sha256 | test("^[0-9a-f]{64}$"))
        and (.scope.files | nni and . > 0)
        and (.scope.functions | nni and . > 0)
        and (.scope.selected_mutations | nni and . > 0)
        and (.outcome.caught | nni)
        and (.outcome.timeouts | nni)
        and (.outcome.missed | nni and . == 0)
        and (.outcome.unviable | nni)
        and (.outcome.viable | nni and . > 0)
        and (.outcome.mutation_score_percent
            | type == "number" and . >= 95 and . <= 100)
        and (.outcome.required_score_percent
            | type == "number" and . >= 95 and . <= 100)
    ' "$summary" >/dev/null || {
        echo "sealed mutation summary has an invalid contract" >&2
        return 1
    }
    jq -e '
        type == "array" and length > 0
        and all(.[]; (.name | type == "string" and length > 0)
            and (.file | type == "string" and length > 0)
            and (.function.function_name | type == "string" and length > 0))
        and ([.[].name] | length == (unique | length))
    ' "$mutants" >/dev/null || {
        echo "sealed mutation inventory is invalid" >&2
        return 1
    }
    jq -e '
        def nni: type == "number" and . >= 0 and . == floor;
        (.cargo_mutants_version | type == "string" and length > 0)
        and (.total_mutants | nni and . > 0)
        and (.caught | nni) and (.missed | nni) and (.unviable | nni)
        and (.timeout | nni)
        and (.outcomes | type == "array" and length > 1)
    ' "$outcomes" >/dev/null || {
        echo "sealed mutation outcomes are invalid" >&2
        return 1
    }

    selected="$(jq -r 'length' "$mutants")"
    caught="$(jq -r '[.outcomes[] | select(.summary == "CaughtMutant")] | length' "$outcomes")"
    missed="$(jq -r '[.outcomes[] | select(.summary == "MissedMutant")] | length' "$outcomes")"
    timeout="$(jq -r '[.outcomes[] | select(.summary == "Timeout")] | length' "$outcomes")"
    unviable="$(jq -r '[.outcomes[] | select(.summary == "Unviable")] | length' "$outcomes")"
    baseline_count="$(jq -r '[.outcomes[] | select(.scenario == "Baseline" and .summary == "Success")] | length' "$outcomes")"
    viable="$((caught + timeout + missed))"
    score="$(jq -r '.outcome.mutation_score_percent' "$summary")"
    required="$(jq -r '.outcome.required_score_percent' "$summary")"
    actual_files="$(jq -r '[.[].file] | unique | length' "$mutants")"
    actual_functions="$(jq -r '[.[].function.function_name] | unique | length' "$mutants")"
    reported_selected="$(jq -r '.scope.selected_mutations' "$summary")"
    reported_caught="$(jq -r '.outcome.caught' "$summary")"
    reported_missed="$(jq -r '.outcome.missed' "$summary")"
    reported_timeout="$(jq -r '.outcome.timeouts' "$summary")"
    reported_unviable="$(jq -r '.outcome.unviable' "$summary")"

    if [ "$baseline_count" -ne 1 ] \
        || [ "$selected" -ne "$((caught + timeout + missed + unviable))" ] \
        || [ "$(jq -r '.outcomes | length' "$outcomes")" -ne "$((selected + 1))" ] \
        || [ "$selected" -ne "$(jq -r '.total_mutants' "$outcomes")" ] \
        || [ "$caught" -ne "$(jq -r '.caught' "$outcomes")" ] \
        || [ "$missed" -ne "$(jq -r '.missed' "$outcomes")" ] \
        || [ "$timeout" -ne "$(jq -r '.timeout' "$outcomes")" ] \
        || [ "$unviable" -ne "$(jq -r '.unviable' "$outcomes")" ] \
        || [ "$selected" -ne "$reported_selected" ] \
        || [ "$caught" -ne "$reported_caught" ] \
        || [ "$missed" -ne 0 ] || [ "$missed" -ne "$reported_missed" ] \
        || [ "$timeout" -ne "$reported_timeout" ] \
        || [ "$unviable" -ne "$reported_unviable" ] \
        || [ "$viable" -ne "$(jq -r '.outcome.viable' "$summary")" ] \
        || [ "$actual_files" -ne "$(jq -r '.scope.files' "$summary")" ] \
        || [ "$actual_functions" -ne "$(jq -r '.scope.functions' "$summary")" ] \
        || [ "$(jq -r '.cargo_mutants_version' "$outcomes")" \
            != "$(jq -r '.cargo_mutants_version' "$summary")" ]; then
        echo "sealed mutation counts do not match the raw completed run" >&2
        return 1
    fi
    if ! awk -v caught="$((caught + timeout))" -v viable="$viable" \
        -v reported="$score" -v required="$required" '
        BEGIN {
            if (viable <= 0 || required < 95 || reported < required) exit 1
            calculated = caught * 100 / viable
            difference = calculated - reported
            if (difference < 0) difference = -difference
            exit !(difference < 0.000001)
        }'; then
        echo "sealed mutation score is inconsistent or below 95%" >&2
        return 1
    fi

    compare_outcome_names "$outcomes" CaughtMutant "$evidence/initial/caught.txt" || return 1
    compare_outcome_names "$outcomes" MissedMutant "$evidence/initial/missed.txt" || return 1
    compare_outcome_names "$outcomes" Timeout "$evidence/initial/timeout.txt" || return 1
    compare_outcome_names "$outcomes" Unviable "$evidence/initial/unviable.txt" || return 1

    inventory="$(mktemp "${TMPDIR:-/tmp}/scorchkit-sealed-inventory.XXXXXX")" || return 1
    outcome_inventory="$(mktemp "${TMPDIR:-/tmp}/scorchkit-sealed-outcomes.XXXXXX")" || {
        rm -f "$inventory"
        return 1
    }
    jq -r '.[].name' "$mutants" | LC_ALL=C sort > "$inventory"
    jq -r '.outcomes[] | select(.scenario | type == "object") | .scenario.Mutant.name' \
        "$outcomes" | LC_ALL=C sort > "$outcome_inventory"
    if ! cmp -s "$inventory" "$outcome_inventory"; then
        rm -f "$inventory" "$outcome_inventory"
        echo "sealed mutation inventory does not match raw outcomes" >&2
        return 1
    fi
    rm -f "$inventory" "$outcome_inventory"

    current_input="$(mutation_input_hash)" || return 1
    if [ "$current_input" != "$(jq -r '.mutation_input_sha256' "$summary")" ]; then
        echo "sealed mutation evidence does not match current mutation-relevant inputs" >&2
        return 1
    fi
    echo "sealed green mutation baseline verified: $((caught + timeout))/$viable viable caught, ${score}% MSI"
    echo "mutation input: $current_input"
    echo "evidence digest: $(evidence_digest "$evidence")"
}

selftest() {
    local evidence fixture input_hash mutant summary_backup
    fixture="$(mktemp -d "${TMPDIR:-/tmp}/scorchkit-sealed-selftest.XXXXXX")" || return 1
    SCORCHKIT_SEALED_FIXTURE="$fixture"
    trap 'rm -rf "${SCORCHKIT_SEALED_FIXTURE:-}"' EXIT
    git -C "$fixture" init -q || return 1
    git -C "$fixture" config user.name 'ScorchKit Sealed Evidence Test'
    git -C "$fixture" config user.email 'sealed-evidence@invalid.example'
    mkdir -p "$fixture/src" "$fixture/tests"
    printf '%s\n' 'pub fn probe() -> bool { true }' > "$fixture/src/lib.rs"
    printf '%s\n' '#[test] fn probe_is_true() { assert!(true); }' > "$fixture/tests/probe.rs"
    printf '%s\n' '[package]' 'name = "probe"' 'version = "0.1.0"' > "$fixture/Cargo.toml"
    git -C "$fixture" add Cargo.toml src/lib.rs tests/probe.rs
    git -C "$fixture" commit -q -m baseline || return 1
    input_hash="$(ROOT_DIR="$fixture" mutation_input_hash)" || return 1
    evidence="$fixture/.git/scorchkit-mutants-focused-ticket-998"
    mkdir -p "$evidence/initial"
    mutant='src/lib.rs:1:1: replace probe -> bool with false'
    printf '[{"name":"%s","file":"src/lib.rs","function":{"function_name":"probe"}}]\n' \
        "$mutant" > "$evidence/initial/mutants.json"
    printf '%s\n' \
        '{"cargo_mutants_version":"selftest","total_mutants":1,"caught":1,"missed":0,"unviable":0,"timeout":0,"outcomes":[' \
        '{"scenario":"Baseline","summary":"Success"},' \
        "{\"scenario\":{\"Mutant\":{\"name\":\"$mutant\"}},\"summary\":\"CaughtMutant\"}" \
        ']}' > "$evidence/initial/outcomes.json"
    printf '%s\n' "$mutant" > "$evidence/initial/caught.txt"
    : > "$evidence/initial/missed.txt"
    : > "$evidence/initial/timeout.txt"
    : > "$evidence/initial/unviable.txt"
    printf '%s\n' \
        '{' \
        '  "ticket": "TICKET-998",' \
        '  "roadmap_item": "SK-998",' \
        '  "mode": "sealed_green_diff",' \
        '  "completed": true,' \
        '  "date": "2026-08-17",' \
        '  "cargo_mutants_version": "selftest",' \
        '  "owner_approval": "selftest",' \
        '  "source_mode": "diff",' \
        '  "full_repository_mutation": "deferred_by_repository_owner",' \
        "  \"mutation_input_sha256\": \"$input_hash\"," \
        '  "scope": {"files": 1, "functions": 1, "selected_mutations": 1},' \
        '  "outcome": {"caught": 1, "timeouts": 0, "missed": 0, "unviable": 0, "viable": 1, "mutation_score_percent": 100, "required_score_percent": 95}' \
        '}' > "$evidence/summary.json"
    ROOT_DIR="$fixture" verify_evidence "$evidence" >/dev/null || return 1
    summary_backup="$fixture/.git/sealed-summary-backup.json"
    jq '.outcome.missed = 1' "$evidence/summary.json" > "$summary_backup" || return 1
    mv "$summary_backup" "$evidence/summary.json"
    if ROOT_DIR="$fixture" verify_evidence "$evidence" >/dev/null 2>&1; then
        echo "sealed mutation selftest failed: a missed mutant was accepted" >&2
        return 1
    fi
    jq '.outcome.missed = 0' "$evidence/summary.json" > "$summary_backup" || return 1
    mv "$summary_backup" "$evidence/summary.json"
    printf '%s\n' 'pub fn probe() -> bool { false }' > "$fixture/src/lib.rs"
    if ROOT_DIR="$fixture" verify_evidence "$evidence" >/dev/null 2>&1; then
        echo "sealed mutation selftest failed: changed mutation input was accepted" >&2
        return 1
    fi
    echo "sealed mutation baseline selftest OK"
}

case "${1:-}" in
    --verify)
        [ "$#" -eq 2 ] || { usage >&2; exit 2; }
        verify_evidence "$2"
        ;;
    --digest)
        [ "$#" -eq 2 ] || { usage >&2; exit 2; }
        evidence_digest "$2"
        ;;
    --selftest)
        [ "$#" -eq 1 ] || { usage >&2; exit 2; }
        selftest
        ;;
    *)
        usage >&2
        exit 2
        ;;
esac
