#!/usr/bin/env bash
# Verify focused mutation-repair evidence without executing cargo-mutants.

set -uo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT_DIR="$(cd "$SCRIPT_DIR/.." && pwd)"
FOCUSED_EVIDENCE_FILES=(
    summary.json
    initial/outcomes.json
    initial/mutants.json
    initial/caught.txt
    initial/missed.txt
    initial/unviable.txt
    recheck/outcomes.json
    recheck/mutants.json
    recheck/caught.txt
    recheck/missed.txt
    recheck/unviable.txt
)
readonly FOCUSED_EVIDENCE_FILES
FOCUSED_FOLLOWUP_FILES=(
    followup-001/base-src-runner-subprocess.rs
    followup-001/outcomes.json
    followup-001/mutants.json
    followup-001/caught.txt
    followup-001/missed.txt
    followup-001/unviable.txt
)
readonly FOCUSED_FOLLOWUP_FILES

usage() {
    cat <<'USAGE'
usage: bin/focused-mutation-evidence.sh COMMAND [ARGS]

  --input-hash [ROOT]
  --verify EVIDENCE_DIR
  --digest EVIDENCE_DIR
  --selftest
USAGE
}

need_tool() {
    local tool="$1"
    command -v "$tool" >/dev/null 2>&1 || {
        echo "focused mutation evidence requires $tool" >&2
        return 1
    }
}

mutation_input_hash() {
    local root="${1:-$ROOT_DIR}"
    local override_relative="${2:-}" override_source="${3:-}"
    local digest entry_count=0 file file_list fingerprint head manifest override_seen=0
    local state_failed=0 target
    local -a scope=(
        Cargo.toml
        Cargo.lock
        rust-toolchain
        rust-toolchain.toml
        build.rs
        .cargo
        .config/nextest.toml
        src
        tests
        examples
        migrations
        rules
    )

    need_tool git || return 1
    need_tool mktemp || return 1
    need_tool shasum || return 1
    git -C "$root" rev-parse --show-toplevel >/dev/null 2>&1 || {
        echo "mutation input root is not a Git worktree: $root" >&2
        return 1
    }
    root="$(git -C "$root" rev-parse --show-toplevel 2>/dev/null)" || return 1
    if [ -n "$override_relative" ]; then
        if [ -z "$override_source" ] || [ ! -f "$override_source" ] || [ -L "$override_source" ]; then
            echo "mutation input override is missing or is a symlink" >&2
            return 1
        fi
    elif [ -n "$override_source" ]; then
        echo "mutation input override requires a repository-relative path" >&2
        return 1
    fi

    file_list="$(mktemp "${TMPDIR:-/tmp}/scorchkit-mutation-inputs.XXXXXX")" || return 1
    manifest="$(mktemp "${TMPDIR:-/tmp}/scorchkit-mutation-manifest.XXXXXX")" || {
        rm -f "$file_list"
        return 1
    }

    if ! {
        git -C "$root" ls-files -z --cached -- "${scope[@]}"
        git -C "$root" ls-files -z --others --exclude-standard -- "${scope[@]}"
    } | LC_ALL=C sort -z -u > "$file_list"; then
        rm -f "$file_list" "$manifest"
        echo "could not enumerate mutation-relevant inputs" >&2
        return 1
    fi

    head="$(git -C "$root" rev-parse HEAD 2>/dev/null)" || {
        rm -f "$file_list" "$manifest"
        echo "could not resolve mutation input HEAD" >&2
        return 1
    }
    printf 'HEAD\0%s\0' "$head" > "$manifest"

    while IFS= read -r -d '' file; do
        if [ -L "$root/$file" ]; then
            target="$(readlink "$root/$file" 2>/dev/null)" || {
                state_failed=1
                break
            }
            printf 'PATH\0%s\0SYMLINK\0%s\0' "$file" "$target" >> "$manifest"
        elif [ -f "$root/$file" ]; then
            if [ -n "$override_relative" ] && [ "$file" = "$override_relative" ]; then
                digest="$(shasum -a 256 < "$override_source" 2>/dev/null | awk '{print $1}')"
                override_seen=$((override_seen + 1))
            else
                digest="$(shasum -a 256 < "$root/$file" 2>/dev/null | awk '{print $1}')"
            fi
            if [ -z "$digest" ]; then
                state_failed=1
                break
            fi
            printf 'PATH\0%s\0FILE\0%s\0' "$file" "$digest" >> "$manifest"
        elif [ ! -e "$root/$file" ]; then
            printf 'PATH\0%s\0MISSING\0' "$file" >> "$manifest"
        else
            state_failed=1
            break
        fi
        entry_count=$((entry_count + 1))
    done < "$file_list"
    rm -f "$file_list"

    if [ "$state_failed" -ne 0 ] || [ "$entry_count" -eq 0 ] \
        || { [ -n "$override_relative" ] && [ "$override_seen" -ne 1 ]; }; then
        rm -f "$manifest"
        echo "could not read a complete mutation input inventory" >&2
        return 1
    fi

    fingerprint="$(shasum -a 256 < "$manifest" 2>/dev/null | awk '{print $1}')"
    rm -f "$manifest"
    [[ "$fingerprint" =~ ^[0-9a-f]{64}$ ]] || {
        echo "could not hash mutation-relevant inputs" >&2
        return 1
    }
    printf '%s\n' "$fingerprint"
}

evidence_file_list() {
    local evidence="$1" relative
    for relative in "${FOCUSED_EVIDENCE_FILES[@]}"; do
        printf '%s\n' "$relative"
    done
    if [ -e "$evidence/followup-001" ]; then
        for relative in "${FOCUSED_FOLLOWUP_FILES[@]}"; do
            printf '%s\n' "$relative"
        done
    fi
}

evidence_files_exist() {
    local evidence="$1" relative

    [ -d "$evidence" ] && [ ! -L "$evidence" ] || {
        echo "focused mutation evidence directory is missing: $evidence" >&2
        return 1
    }
    if [ -e "$evidence/followup-001" ] \
        && { [ ! -d "$evidence/followup-001" ] || [ -L "$evidence/followup-001" ]; }; then
        echo "focused mutation follow-up directory is invalid" >&2
        return 1
    fi
    while IFS= read -r relative; do
        if [ ! -f "$evidence/$relative" ] || [ -L "$evidence/$relative" ]; then
            echo "focused mutation evidence file is missing or is a symlink: $relative" >&2
            return 1
        fi
    done < <(evidence_file_list "$evidence")
}

evidence_digest() {
    local evidence="$1" digest manifest relative result

    need_tool mktemp || return 1
    need_tool shasum || return 1
    evidence_files_exist "$evidence" || return 1
    manifest="$(mktemp "${TMPDIR:-/tmp}/scorchkit-focused-evidence.XXXXXX")" || return 1
    : > "$manifest"
    while IFS= read -r relative; do
        digest="$(shasum -a 256 < "$evidence/$relative" | awk '{print $1}')"
        [[ "$digest" =~ ^[0-9a-f]{64}$ ]] || {
            rm -f "$manifest"
            echo "could not hash focused mutation evidence: $relative" >&2
            return 1
        }
        printf 'PATH\0%s\0FILE\0%s\0' "$relative" "$digest" >> "$manifest"
    done < <(evidence_file_list "$evidence")
    result="$(shasum -a 256 < "$manifest" | awk '{print $1}')"
    rm -f "$manifest"
    [[ "$result" =~ ^[0-9a-f]{64}$ ]] || return 1
    printf '%s\n' "$result"
}

compare_outcome_names() {
    local outcomes="$1" summary="$2" names="$3" actual expected
    actual="$(mktemp "${TMPDIR:-/tmp}/scorchkit-outcome-names.XXXXXX")" || return 1
    expected="$(mktemp "${TMPDIR:-/tmp}/scorchkit-evidence-names.XXXXXX")" || {
        rm -f "$actual"
        return 1
    }
    jq -r --arg summary "$summary" \
        '.outcomes[] | select(.summary == $summary) | .scenario.Mutant.name' \
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
        echo "focused mutation name list does not match outcomes: $names" >&2
        return 1
    fi
    rm -f "$actual" "$expected"
}

verify_evidence() {
    local evidence="$1" summary initial_outcomes initial_mutants recheck_outcomes recheck_mutants
    local initial_selected initial_caught initial_missed initial_unviable initial_timeout
    local recheck_selected recheck_caught recheck_missed recheck_unviable recheck_timeout
    local summary_selected summary_files summary_functions summary_mutated_functions summary_initial_caught
    local summary_initial_missed summary_initial_unviable summary_recheck_selected
    local summary_recheck_caught summary_recheck_missed summary_recheck_unviable
    local final_caught final_missed final_unviable final_viable final_score required_score
    local actual_files actual_functions baseline_followup=0 baseline_initial baseline_recheck
    local current_input sealed_input followup_version="" initial_version recheck_version numeric
    local initial_inventory recheck_inventory initial_missed_names recheck_caught_names result_digest
    local base_input followup_base_snapshot followup_base_snapshot_sha followup_caught=0
    local followup_expected_functions followup_file followup_functions followup_inventory
    local followup_missed=0
    local followup_mutants followup_outcomes followup_selected=0 followup_score=0
    local followup_timeout=0 followup_unviable=0 hypothetical_base snapshot_sha
    local summary_followup_caught=0 summary_followup_missed=0 summary_followup_selected=0
    local summary_followup_unviable=0

    need_tool cmp || return 1
    need_tool jq || return 1
    evidence_files_exist "$evidence" || return 1

    summary="$evidence/summary.json"
    initial_outcomes="$evidence/initial/outcomes.json"
    initial_mutants="$evidence/initial/mutants.json"
    recheck_outcomes="$evidence/recheck/outcomes.json"
    recheck_mutants="$evidence/recheck/mutants.json"

    if ! jq -e '
        .ticket | test("^TICKET-[0-9]+$")
    ' "$summary" >/dev/null \
        || ! jq -e '
            def nni: type == "number" and . >= 0 and . == floor;
            .mode == "focused_repaired_functions"
            and .completed == true
            and (.date | type == "string" and test("^[0-9]{4}-[0-9]{2}-[0-9]{2}$"))
            and (.cargo_mutants_version | type == "string" and length > 0)
            and .full_repository_mutation == "deferred_by_repository_owner"
            and (.mutation_input_sha256 | test("^[0-9a-f]{64}$"))
            and ((.base_mutation_input_sha256 // .mutation_input_sha256)
                | test("^[0-9a-f]{64}$"))
            and (.scope.files | nni and . > 0)
            and (.scope.functions | nni and . > 0)
            and (.scope.mutated_functions | nni and . > 0)
            and (.scope.selected_mutations | nni and . > 0)
            and (.initial_run.caught | nni)
            and (.initial_run.missed | nni)
            and (.initial_run.unviable | nni)
            and (.exact_recheck.selected_mutations | nni and . > 0)
            and (.exact_recheck.caught | nni)
            and (.exact_recheck.missed | nni)
            and (.exact_recheck.unviable | nni)
            and (.final_outcome.caught | nni)
            and (.final_outcome.missed | nni)
            and (.final_outcome.unviable | nni)
            and (.final_outcome.viable | nni and . > 0)
            and (.final_outcome.mutation_score_percent
                | type == "number" and . >= 0 and . <= 100)
            and (.final_outcome.required_score_percent
                | type == "number" and . >= 95 and . <= 100)
            and ((has("focused_followup") | not) or (
                .focused_followup.id == "followup-001"
                and (.focused_followup.reason | type == "string" and length > 0)
                and (.focused_followup.changed_file | type == "string" and length > 0)
                and .focused_followup.baseline_snapshot
                    == "followup-001/base-src-runner-subprocess.rs"
                and (.focused_followup.baseline_snapshot_sha256
                    | test("^[0-9a-f]{64}$"))
                and (.focused_followup.functions | type == "array" and length > 0
                    and all(.[]; type == "string" and length > 0)
                    and length == (unique | length))
                and (.focused_followup.selected_mutations | nni and . > 0)
                and (.focused_followup.caught | nni)
                and (.focused_followup.missed | nni)
                and (.focused_followup.unviable | nni)
                and (.focused_followup.mutation_score_percent
                    | type == "number" and . >= 0 and . <= 100)
            ))
        ' "$summary" >/dev/null; then
        echo "focused mutation summary has an invalid contract" >&2
        return 1
    fi
    if ! jq -e '
            type == "array" and length > 0
            and all(.[]; (.name | type == "string" and length > 0)
                and (.file | type == "string" and length > 0)
                and (.function.function_name | type == "string" and length > 0))
            and ([.[].name] | length == (unique | length))
        ' "$initial_mutants" >/dev/null \
        || ! jq -e '
            type == "array" and length > 0
            and all(.[]; (.name | type == "string" and length > 0)
                and (.file | type == "string" and length > 0)
                and (.function.function_name | type == "string" and length > 0))
            and ([.[].name] | length == (unique | length))
        ' "$recheck_mutants" >/dev/null \
        || ! jq -e '
            def nni: type == "number" and . >= 0 and . == floor;
            (.cargo_mutants_version | type == "string" and length > 0)
            and (.total_mutants | nni and . > 0)
            and (.caught | nni) and (.missed | nni) and (.unviable | nni)
            and (.timeout | nni)
            and (.outcomes | type == "array" and length > 0)
        ' "$initial_outcomes" >/dev/null \
        || ! jq -e '
            def nni: type == "number" and . >= 0 and . == floor;
            (.cargo_mutants_version | type == "string" and length > 0)
            and (.total_mutants | nni and . > 0)
            and (.caught | nni) and (.missed | nni) and (.unviable | nni)
            and (.timeout | nni)
            and (.outcomes | type == "array" and length > 0)
        ' "$recheck_outcomes" >/dev/null; then
        echo "focused mutation outcome or inventory JSON is invalid" >&2
        return 1
    fi

    if jq -e 'has("focused_followup")' "$summary" >/dev/null; then
        [ -d "$evidence/followup-001" ] && [ ! -L "$evidence/followup-001" ] || {
            echo "focused mutation summary requires follow-up evidence" >&2
            return 1
        }
        followup_outcomes="$evidence/followup-001/outcomes.json"
        followup_mutants="$evidence/followup-001/mutants.json"
        if ! jq -e '
                type == "array" and length > 0
                and all(.[]; (.name | type == "string" and length > 0)
                    and .file == "src/runner/subprocess.rs"
                    and (.function.function_name | type == "string" and length > 0))
                and ([.[].name] | length == (unique | length))
            ' "$followup_mutants" >/dev/null \
            || ! jq -e '
                def nni: type == "number" and . >= 0 and . == floor;
                (.cargo_mutants_version | type == "string" and length > 0)
                and (.total_mutants | nni and . > 0)
                and (.caught | nni) and (.missed | nni) and (.unviable | nni)
                and (.timeout | nni)
                and (.outcomes | type == "array" and length > 0)
            ' "$followup_outcomes" >/dev/null; then
            echo "focused mutation follow-up outcome or inventory JSON is invalid" >&2
            return 1
        fi
    elif [ -e "$evidence/followup-001" ]; then
        echo "focused mutation follow-up evidence is not declared by the summary" >&2
        return 1
    fi

    initial_selected="$(jq -r 'length' "$initial_mutants")"
    initial_caught="$(jq -r '[.outcomes[] | select(.summary == "CaughtMutant")] | length' "$initial_outcomes")"
    initial_missed="$(jq -r '[.outcomes[] | select(.summary == "MissedMutant")] | length' "$initial_outcomes")"
    initial_unviable="$(jq -r '[.outcomes[] | select(.summary == "Unviable")] | length' "$initial_outcomes")"
    initial_timeout="$(jq -r '[.outcomes[] | select(.summary == "Timeout")] | length' "$initial_outcomes")"
    recheck_selected="$(jq -r 'length' "$recheck_mutants")"
    recheck_caught="$(jq -r '[.outcomes[] | select(.summary == "CaughtMutant")] | length' "$recheck_outcomes")"
    recheck_missed="$(jq -r '[.outcomes[] | select(.summary == "MissedMutant")] | length' "$recheck_outcomes")"
    recheck_unviable="$(jq -r '[.outcomes[] | select(.summary == "Unviable")] | length' "$recheck_outcomes")"
    recheck_timeout="$(jq -r '[.outcomes[] | select(.summary == "Timeout")] | length' "$recheck_outcomes")"
    baseline_initial="$(jq -r '[.outcomes[] | select(.scenario == "Baseline" and .summary == "Success")] | length' "$initial_outcomes")"
    baseline_recheck="$(jq -r '[.outcomes[] | select(.scenario == "Baseline" and .summary == "Success")] | length' "$recheck_outcomes")"

    summary_selected="$(jq -r '.scope.selected_mutations' "$summary")"
    summary_files="$(jq -r '.scope.files' "$summary")"
    summary_functions="$(jq -r '.scope.functions' "$summary")"
    summary_mutated_functions="$(jq -r '.scope.mutated_functions' "$summary")"
    summary_initial_caught="$(jq -r '.initial_run.caught' "$summary")"
    summary_initial_missed="$(jq -r '.initial_run.missed' "$summary")"
    summary_initial_unviable="$(jq -r '.initial_run.unviable' "$summary")"
    summary_recheck_selected="$(jq -r '.exact_recheck.selected_mutations' "$summary")"
    summary_recheck_caught="$(jq -r '.exact_recheck.caught' "$summary")"
    summary_recheck_missed="$(jq -r '.exact_recheck.missed' "$summary")"
    summary_recheck_unviable="$(jq -r '.exact_recheck.unviable' "$summary")"
    final_caught="$(jq -r '.final_outcome.caught' "$summary")"
    final_missed="$(jq -r '.final_outcome.missed' "$summary")"
    final_unviable="$(jq -r '.final_outcome.unviable' "$summary")"
    final_viable="$(jq -r '.final_outcome.viable' "$summary")"
    final_score="$(jq -r '.final_outcome.mutation_score_percent' "$summary")"
    required_score="$(jq -r '.final_outcome.required_score_percent' "$summary")"
    actual_files="$(jq -r '[.[].file] | unique | length' "$initial_mutants")"
    actual_functions="$(jq -r '[.[].function.function_name] | unique | length' "$initial_mutants")"
    initial_version="$(jq -r '.cargo_mutants_version' "$initial_outcomes")"
    recheck_version="$(jq -r '.cargo_mutants_version' "$recheck_outcomes")"
    if [ -n "$followup_outcomes" ]; then
        followup_selected="$(jq -r 'length' "$followup_mutants")"
        followup_caught="$(jq -r '[.outcomes[] | select(.summary == "CaughtMutant")] | length' "$followup_outcomes")"
        followup_missed="$(jq -r '[.outcomes[] | select(.summary == "MissedMutant")] | length' "$followup_outcomes")"
        followup_unviable="$(jq -r '[.outcomes[] | select(.summary == "Unviable")] | length' "$followup_outcomes")"
        followup_timeout="$(jq -r '[.outcomes[] | select(.summary == "Timeout")] | length' "$followup_outcomes")"
        baseline_followup="$(jq -r '[.outcomes[] | select(.scenario == "Baseline" and .summary == "Success")] | length' "$followup_outcomes")"
        followup_version="$(jq -r '.cargo_mutants_version' "$followup_outcomes")"
        summary_followup_selected="$(jq -r '.focused_followup.selected_mutations' "$summary")"
        summary_followup_caught="$(jq -r '.focused_followup.caught' "$summary")"
        summary_followup_missed="$(jq -r '.focused_followup.missed' "$summary")"
        summary_followup_unviable="$(jq -r '.focused_followup.unviable' "$summary")"
        followup_score="$(jq -r '.focused_followup.mutation_score_percent' "$summary")"
    fi

    for numeric in "$initial_selected" "$initial_caught" "$initial_missed" \
        "$initial_unviable" "$initial_timeout" "$recheck_selected" "$recheck_caught" \
        "$recheck_missed" "$recheck_unviable" "$recheck_timeout" "$summary_selected" \
        "$summary_files" "$summary_functions" "$summary_mutated_functions" \
        "$summary_initial_caught" "$summary_initial_missed" "$summary_initial_unviable" \
        "$summary_recheck_selected" "$summary_recheck_caught" "$summary_recheck_missed" \
        "$summary_recheck_unviable" "$final_caught" "$final_missed" "$final_unviable" \
        "$final_viable" "$actual_files" "$actual_functions" "$followup_selected" \
        "$followup_caught" "$followup_missed" "$followup_unviable" "$followup_timeout" \
        "$summary_followup_selected" "$summary_followup_caught" \
        "$summary_followup_missed" "$summary_followup_unviable"; do
        [[ "$numeric" =~ ^[0-9]+$ ]] || {
            echo "focused mutation evidence contains a non-integer count" >&2
            return 1
        }
    done
    if ! [[ "$final_score" =~ ^[0-9]+([.][0-9]+)?$ ]] \
        || ! [[ "$required_score" =~ ^[0-9]+([.][0-9]+)?$ ]] \
        || ! [[ "$followup_score" =~ ^[0-9]+([.][0-9]+)?$ ]]; then
        echo "focused mutation evidence contains an invalid score" >&2
        return 1
    fi

    if [ "$baseline_initial" -ne 1 ] || [ "$baseline_recheck" -ne 1 ] \
        || [ "$initial_timeout" -ne 0 ] || [ "$recheck_timeout" -ne 0 ] \
        || [ "$initial_version" != "$recheck_version" ] \
        || [ "$initial_version" != "$(jq -r '.cargo_mutants_version' "$summary")" ] \
        || { [ -n "$followup_outcomes" ] \
            && { [ "$baseline_followup" -ne 1 ] || [ "$followup_timeout" -ne 0 ] \
                || [ "$followup_version" != "$initial_version" ]; }; }; then
        echo "focused mutation runs require one successful baseline and no timeouts" >&2
        return 1
    fi
    if [ "$initial_selected" -ne "$((initial_caught + initial_missed + initial_unviable))" ] \
        || [ "$(jq -r '.outcomes | length' "$initial_outcomes")" -ne "$((initial_selected + 1))" ] \
        || [ "$initial_selected" -ne "$summary_selected" ] \
        || [ "$initial_selected" -ne "$(jq -r '.total_mutants' "$initial_outcomes")" ] \
        || [ "$initial_caught" -ne "$(jq -r '.caught' "$initial_outcomes")" ] \
        || [ "$initial_missed" -ne "$(jq -r '.missed' "$initial_outcomes")" ] \
        || [ "$initial_unviable" -ne "$(jq -r '.unviable' "$initial_outcomes")" ] \
        || [ "$initial_timeout" -ne "$(jq -r '.timeout' "$initial_outcomes")" ] \
        || [ "$initial_caught" -ne "$summary_initial_caught" ] \
        || [ "$initial_missed" -ne "$summary_initial_missed" ] \
        || [ "$initial_unviable" -ne "$summary_initial_unviable" ] \
        || [ "$actual_files" -ne "$summary_files" ] \
        || [ "$actual_functions" -ne "$summary_mutated_functions" ] \
        || [ "$summary_functions" -lt "$summary_mutated_functions" ]; then
        echo "focused mutation initial-run counts do not match the sealed summary" >&2
        return 1
    fi
    if [ "$recheck_selected" -ne "$((recheck_caught + recheck_missed + recheck_unviable))" ] \
        || [ "$(jq -r '.outcomes | length' "$recheck_outcomes")" -ne "$((recheck_selected + 1))" ] \
        || [ "$recheck_selected" -ne "$summary_recheck_selected" ] \
        || [ "$recheck_selected" -ne "$(jq -r '.total_mutants' "$recheck_outcomes")" ] \
        || [ "$recheck_caught" -ne "$(jq -r '.caught' "$recheck_outcomes")" ] \
        || [ "$recheck_missed" -ne "$(jq -r '.missed' "$recheck_outcomes")" ] \
        || [ "$recheck_unviable" -ne "$(jq -r '.unviable' "$recheck_outcomes")" ] \
        || [ "$recheck_timeout" -ne "$(jq -r '.timeout' "$recheck_outcomes")" ] \
        || [ "$recheck_caught" -ne "$summary_recheck_caught" ] \
        || [ "$recheck_missed" -ne "$summary_recheck_missed" ] \
        || [ "$recheck_unviable" -ne "$summary_recheck_unviable" ]; then
        echo "focused mutation exact-recheck counts do not match the sealed summary" >&2
        return 1
    fi
    if [ -n "$followup_outcomes" ]; then
        if [ "$followup_selected" -ne "$((followup_caught + followup_missed + followup_unviable))" ] \
            || [ "$(jq -r '.outcomes | length' "$followup_outcomes")" -ne "$((followup_selected + 1))" ] \
            || [ "$followup_selected" -ne "$(jq -r '.total_mutants' "$followup_outcomes")" ] \
            || [ "$followup_caught" -ne "$(jq -r '.caught' "$followup_outcomes")" ] \
            || [ "$followup_missed" -ne "$(jq -r '.missed' "$followup_outcomes")" ] \
            || [ "$followup_unviable" -ne "$(jq -r '.unviable' "$followup_outcomes")" ] \
            || [ "$followup_timeout" -ne "$(jq -r '.timeout' "$followup_outcomes")" ] \
            || [ "$followup_selected" -ne "$summary_followup_selected" ] \
            || [ "$followup_caught" -ne "$summary_followup_caught" ] \
            || [ "$followup_missed" -ne "$summary_followup_missed" ] \
            || [ "$followup_unviable" -ne "$summary_followup_unviable" ] \
            || [ "$followup_missed" -ne 0 ]; then
            echo "focused mutation follow-up counts do not match the sealed summary" >&2
            return 1
        fi
        if ! awk -v caught="$followup_caught" -v viable="$((followup_caught + followup_missed))" \
            -v reported="$followup_score" \
            'BEGIN {
                if (viable <= 0 || reported < 95) exit 1
                calculated = caught * 100 / viable
                difference = calculated - reported
                if (difference < 0) difference = -difference
                exit !(difference < 0.000001)
            }'; then
            echo "focused mutation follow-up score is inconsistent or below 95%" >&2
            return 1
        fi
        compare_outcome_names "$followup_outcomes" CaughtMutant \
            "$evidence/followup-001/caught.txt" || return 1
        compare_outcome_names "$followup_outcomes" MissedMutant \
            "$evidence/followup-001/missed.txt" || return 1
        compare_outcome_names "$followup_outcomes" Unviable \
            "$evidence/followup-001/unviable.txt" || return 1

        followup_inventory="$(mktemp "${TMPDIR:-/tmp}/scorchkit-followup-inventory.XXXXXX")" \
            || return 1
        followup_functions="$(mktemp "${TMPDIR:-/tmp}/scorchkit-followup-functions.XXXXXX")" \
            || { rm -f "$followup_inventory"; return 1; }
        followup_expected_functions="$(mktemp "${TMPDIR:-/tmp}/scorchkit-followup-expected.XXXXXX")" \
            || { rm -f "$followup_inventory" "$followup_functions"; return 1; }
        jq -r '.[].name' "$followup_mutants" | LC_ALL=C sort > "$followup_inventory"
        jq -r '.outcomes[] | select(.scenario | type == "object") | .scenario.Mutant.name' \
            "$followup_outcomes" | LC_ALL=C sort > "$followup_expected_functions"
        if ! cmp -s "$followup_inventory" "$followup_expected_functions"; then
            rm -f "$followup_inventory" "$followup_functions" "$followup_expected_functions"
            echo "follow-up mutation inventory does not match follow-up outcomes" >&2
            return 1
        fi
        jq -r '[.[].function.function_name] | unique[]' "$followup_mutants" \
            | LC_ALL=C sort > "$followup_functions"
        jq -r '.focused_followup.functions[]' "$summary" \
            | LC_ALL=C sort > "$followup_expected_functions"
        if ! cmp -s "$followup_functions" "$followup_expected_functions"; then
            rm -f "$followup_inventory" "$followup_functions" "$followup_expected_functions"
            echo "follow-up function scope does not match the sealed summary" >&2
            return 1
        fi
        rm -f "$followup_inventory" "$followup_functions" "$followup_expected_functions"
    fi
    if [ "$initial_missed" -ne "$recheck_selected" ] \
        || [ "$recheck_caught" -ne "$recheck_selected" ] \
        || [ "$recheck_missed" -ne 0 ] || [ "$recheck_unviable" -ne 0 ] \
        || [ "$final_caught" -ne "$((initial_caught + recheck_caught + followup_caught))" ] \
        || [ "$final_missed" -ne 0 ] \
        || [ "$final_unviable" -ne "$((initial_unviable + recheck_unviable + followup_unviable))" ] \
        || [ "$final_viable" -ne "$((final_caught + final_missed))" ]; then
        echo "focused mutation repair arithmetic is inconsistent" >&2
        return 1
    fi
    if ! awk -v caught="$final_caught" -v viable="$final_viable" -v reported="$final_score" \
        -v required="$required_score" \
        'BEGIN {
            if (viable <= 0 || required < 95 || reported < required) exit 1
            calculated = caught * 100 / viable
            difference = calculated - reported
            if (difference < 0) difference = -difference
            exit !(difference < 0.000001)
        }'; then
        echo "focused mutation score is inconsistent or below the 95% floor" >&2
        return 1
    fi

    compare_outcome_names "$initial_outcomes" CaughtMutant "$evidence/initial/caught.txt" || return 1
    compare_outcome_names "$initial_outcomes" MissedMutant "$evidence/initial/missed.txt" || return 1
    compare_outcome_names "$initial_outcomes" Unviable "$evidence/initial/unviable.txt" || return 1
    compare_outcome_names "$recheck_outcomes" CaughtMutant "$evidence/recheck/caught.txt" || return 1
    compare_outcome_names "$recheck_outcomes" MissedMutant "$evidence/recheck/missed.txt" || return 1
    compare_outcome_names "$recheck_outcomes" Unviable "$evidence/recheck/unviable.txt" || return 1

    initial_inventory="$(mktemp "${TMPDIR:-/tmp}/scorchkit-initial-inventory.XXXXXX")" || return 1
    recheck_inventory="$(mktemp "${TMPDIR:-/tmp}/scorchkit-recheck-inventory.XXXXXX")" || {
        rm -f "$initial_inventory"
        return 1
    }
    initial_missed_names="$(mktemp "${TMPDIR:-/tmp}/scorchkit-initial-missed.XXXXXX")" || {
        rm -f "$initial_inventory" "$recheck_inventory"
        return 1
    }
    recheck_caught_names="$(mktemp "${TMPDIR:-/tmp}/scorchkit-recheck-caught.XXXXXX")" || {
        rm -f "$initial_inventory" "$recheck_inventory" "$initial_missed_names"
        return 1
    }
    jq -r '.[].name' "$initial_mutants" | LC_ALL=C sort > "$initial_inventory"
    jq -r '.outcomes[] | select(.scenario | type == "object") | .scenario.Mutant.name' \
        "$initial_outcomes" | LC_ALL=C sort > "$recheck_inventory"
    if ! cmp -s "$initial_inventory" "$recheck_inventory"; then
        rm -f "$initial_inventory" "$recheck_inventory" "$initial_missed_names" "$recheck_caught_names"
        echo "initial mutation inventory does not match initial outcomes" >&2
        return 1
    fi
    jq -r '.outcomes[] | select(.summary == "MissedMutant") | .scenario.Mutant.name' \
        "$initial_outcomes" | LC_ALL=C sort > "$initial_missed_names"
    jq -r '.[].name' "$recheck_mutants" | LC_ALL=C sort > "$recheck_inventory"
    jq -r '.outcomes[] | select(.summary == "CaughtMutant") | .scenario.Mutant.name' \
        "$recheck_outcomes" | LC_ALL=C sort > "$recheck_caught_names"
    if ! cmp -s "$initial_missed_names" "$recheck_inventory" \
        || ! cmp -s "$initial_missed_names" "$recheck_caught_names"; then
        rm -f "$initial_inventory" "$recheck_inventory" "$initial_missed_names" "$recheck_caught_names"
        echo "exact recheck does not match the complete initial survivor set" >&2
        return 1
    fi
    rm -f "$initial_inventory" "$recheck_inventory" "$initial_missed_names" "$recheck_caught_names"

    base_input="$(jq -r '.base_mutation_input_sha256 // .mutation_input_sha256' "$summary")"
    sealed_input="$(jq -r '.mutation_input_sha256' "$summary")"
    current_input="$(mutation_input_hash "$ROOT_DIR")" || return 1
    if [ "$sealed_input" != "$current_input" ]; then
        echo "focused mutation evidence does not match current mutation-relevant inputs" >&2
        return 1
    fi
    if [ -n "$followup_outcomes" ]; then
        followup_file="$(jq -r '.focused_followup.changed_file' "$summary")"
        followup_base_snapshot="$(jq -r '.focused_followup.baseline_snapshot' "$summary")"
        followup_base_snapshot_sha="$(jq -r '.focused_followup.baseline_snapshot_sha256' "$summary")"
        if [ "$followup_file" != "src/runner/subprocess.rs" ] \
            || [ ! -f "$evidence/$followup_base_snapshot" ] \
            || [ -L "$evidence/$followup_base_snapshot" ] \
            || cmp -s "$ROOT_DIR/$followup_file" "$evidence/$followup_base_snapshot"; then
            echo "focused mutation follow-up source transition is invalid" >&2
            return 1
        fi
        snapshot_sha="$(shasum -a 256 < "$evidence/$followup_base_snapshot" | awk '{print $1}')"
        if [ "$snapshot_sha" != "$followup_base_snapshot_sha" ]; then
            echo "focused mutation follow-up baseline snapshot digest is invalid" >&2
            return 1
        fi
        hypothetical_base="$(mutation_input_hash \
            "$ROOT_DIR" "$followup_file" "$evidence/$followup_base_snapshot")" || return 1
        if [ "$hypothetical_base" != "$base_input" ]; then
            echo "focused mutation follow-up changed inputs outside its sealed file" >&2
            return 1
        fi
    elif [ "$base_input" != "$current_input" ]; then
        echo "focused mutation base input does not match current inputs" >&2
        return 1
    fi
    result_digest="$(evidence_digest "$evidence")" || return 1
    echo "focused mutation evidence verified: $final_caught/$final_viable viable caught, ${final_score}% MSI"
    echo "mutation input: $current_input"
    echo "evidence digest: $result_digest"
}

selftest() {
    local current_hash evidence evidence_name evidence_sha fixture followup_name input_hash mutant_name
    local receipt snapshot_sha summary_backup
    fixture="$(mktemp -d "${TMPDIR:-/tmp}/scorchkit-focused-selftest.XXXXXX")" || return 1
    SCORCHKIT_FOCUSED_FIXTURE="$fixture"
    trap 'rm -rf "${SCORCHKIT_FOCUSED_FIXTURE:-}"' EXIT
    git -C "$fixture" init -q || return 1
    git -C "$fixture" config user.name 'ScorchKit Focused Evidence Test'
    git -C "$fixture" config user.email 'focused-evidence@invalid.example'
    mkdir -p "$fixture/src/runner" "$fixture/tests"
    printf '%s\n' 'pub fn probe() -> bool { true }' > "$fixture/src/lib.rs"
    printf '%s\n' 'pub fn stop_owned_process() -> bool { true }' \
        > "$fixture/src/runner/subprocess.rs"
    printf '%s\n' '#[test] fn probe_is_true() { assert!(true); }' > "$fixture/tests/probe.rs"
    printf '%s\n' '[package]' 'name = "probe"' 'version = "0.1.0"' > "$fixture/Cargo.toml"
    git -C "$fixture" add Cargo.toml src/lib.rs src/runner/subprocess.rs tests/probe.rs
    git -C "$fixture" commit -q -m baseline || return 1
    input_hash="$(mutation_input_hash "$fixture")" || return 1
    evidence="$fixture/.git/scorchkit-mutants-focused-ticket-999"
    mkdir -p "$evidence/initial" "$evidence/recheck"
    mutant_name='src/lib.rs:1:1: replace probe -> bool with false'

    printf '[{"name":"%s","file":"src/lib.rs","function":{"function_name":"probe"}}]\n' \
        "$mutant_name" > "$evidence/initial/mutants.json"
    cp "$evidence/initial/mutants.json" "$evidence/recheck/mutants.json"
    printf '%s\n' \
        '{"cargo_mutants_version":"selftest","total_mutants":1,"caught":0,"missed":1,"unviable":0,"timeout":0,"outcomes":[' \
        '{"scenario":"Baseline","summary":"Success"},' \
        "{\"scenario\":{\"Mutant\":{\"name\":\"$mutant_name\"}},\"summary\":\"MissedMutant\"}" \
        ']}' > "$evidence/initial/outcomes.json"
    printf '%s\n' \
        '{"cargo_mutants_version":"selftest","total_mutants":1,"caught":1,"missed":0,"unviable":0,"timeout":0,"outcomes":[' \
        '{"scenario":"Baseline","summary":"Success"},' \
        "{\"scenario\":{\"Mutant\":{\"name\":\"$mutant_name\"}},\"summary\":\"CaughtMutant\"}" \
        ']}' > "$evidence/recheck/outcomes.json"
    : > "$evidence/initial/caught.txt"
    printf '%s\n' "$mutant_name" > "$evidence/initial/missed.txt"
    : > "$evidence/initial/unviable.txt"
    printf '%s\n' "$mutant_name" > "$evidence/recheck/caught.txt"
    : > "$evidence/recheck/missed.txt"
    : > "$evidence/recheck/unviable.txt"
    printf '%s\n' \
        '{' \
        '  "ticket": "TICKET-999",' \
        '  "mode": "focused_repaired_functions",' \
        '  "completed": true,' \
        '  "date": "2026-08-16",' \
        '  "cargo_mutants_version": "selftest",' \
        "  \"mutation_input_sha256\": \"$input_hash\"," \
        '  "scope": {"files": 1, "functions": 1, "mutated_functions": 1, "selected_mutations": 1},' \
        '  "initial_run": {"caught": 0, "missed": 1, "unviable": 0},' \
        '  "exact_recheck": {"selected_mutations": 1, "caught": 1, "missed": 0, "unviable": 0},' \
        '  "final_outcome": {"caught": 1, "missed": 0, "unviable": 0, "viable": 1, "mutation_score_percent": 100, "required_score_percent": 95},' \
        '  "full_repository_mutation": "deferred_by_repository_owner"' \
        '}' > "$evidence/summary.json"

    ROOT_DIR="$fixture" verify_evidence "$evidence" >/dev/null || return 1
    mkdir -p "$fixture/bin"
    cp "$SCRIPT_DIR/focused-mutation-evidence.sh" "$fixture/bin/focused-mutation-evidence.sh"
    evidence_name="$(basename "$evidence")"
    evidence_sha="$(ROOT_DIR="$fixture" evidence_digest "$evidence")" || return 1
    receipt="$fixture/.git/test-focused-receipt"
    SCORCHKIT_PROJECT_ROOT="$fixture" SCORCHKIT_GATE_RECEIPT="$receipt" \
        SCORCHKIT_GATE_MODE=focused-repair \
        SCORCHKIT_GATE_EVIDENCE_NAME="$evidence_name" \
        SCORCHKIT_GATE_EVIDENCE_DIGEST="$evidence_sha" \
        bash -c '. "$1"; scorchkit_write_gate_receipt && scorchkit_verify_gate_receipt' \
        _ "$SCRIPT_DIR/gate-state.sh" || return 1
    grep -Fqx 'mode=focused-repair' "$receipt" || {
        echo "focused mutation selftest failed: focused receipt mode was not recorded" >&2
        return 1
    }
    summary_backup="$fixture/.git/summary-backup.json"
    cp "$evidence/summary.json" "$summary_backup"
    printf '\n' >> "$evidence/summary.json"
    if SCORCHKIT_PROJECT_ROOT="$fixture" SCORCHKIT_GATE_RECEIPT="$receipt" \
        bash -c '. "$1"; scorchkit_verify_gate_receipt' _ "$SCRIPT_DIR/gate-state.sh" \
        >/dev/null 2>&1; then
        echo "focused mutation selftest failed: changed focused evidence was accepted" >&2
        return 1
    fi
    mv "$summary_backup" "$evidence/summary.json"
    SCORCHKIT_PROJECT_ROOT="$fixture" SCORCHKIT_GATE_RECEIPT="$receipt" \
        bash -c '. "$1"; scorchkit_verify_gate_receipt' _ "$SCRIPT_DIR/gate-state.sh" \
        >/dev/null || return 1
    printf '%s\n' 'pub fn probe() -> bool { false }' > "$fixture/src/lib.rs"
    if ROOT_DIR="$fixture" verify_evidence "$evidence" >/dev/null 2>&1; then
        echo "focused mutation selftest failed: changed Rust input was accepted" >&2
        return 1
    fi
    printf '%s\n' 'pub fn probe() -> bool { true }' > "$fixture/src/lib.rs"
    printf '%s\n' '[{"name":"wrong mutant","file":"src/lib.rs","function":{"function_name":"probe"}}]' \
        > "$evidence/recheck/mutants.json"
    if ROOT_DIR="$fixture" verify_evidence "$evidence" >/dev/null 2>&1; then
        echo "focused mutation selftest failed: mismatched survivor recheck was accepted" >&2
        return 1
    fi
    cp "$evidence/initial/mutants.json" "$evidence/recheck/mutants.json"

    mkdir -p "$evidence/followup-001"
    cp "$fixture/src/runner/subprocess.rs" \
        "$evidence/followup-001/base-src-runner-subprocess.rs"
    snapshot_sha="$(shasum -a 256 \
        < "$evidence/followup-001/base-src-runner-subprocess.rs" | awk '{print $1}')"
    printf '%s\n' 'pub fn stop_owned_process() -> bool { false }' \
        > "$fixture/src/runner/subprocess.rs"
    current_hash="$(mutation_input_hash "$fixture")" || return 1
    followup_name='src/runner/subprocess.rs:1:1: replace stop_owned_process -> bool with true'
    printf '[{"name":"%s","file":"src/runner/subprocess.rs","function":{"function_name":"stop_owned_process"}}]\n' \
        "$followup_name" > "$evidence/followup-001/mutants.json"
    printf '%s\n' \
        '{"cargo_mutants_version":"selftest","total_mutants":1,"caught":1,"missed":0,"unviable":0,"timeout":0,"outcomes":[' \
        '{"scenario":"Baseline","summary":"Success"},' \
        "{\"scenario\":{\"Mutant\":{\"name\":\"$followup_name\"}},\"summary\":\"CaughtMutant\"}" \
        ']}' > "$evidence/followup-001/outcomes.json"
    printf '%s\n' "$followup_name" > "$evidence/followup-001/caught.txt"
    : > "$evidence/followup-001/missed.txt"
    : > "$evidence/followup-001/unviable.txt"
    jq --arg base "$input_hash" --arg current "$current_hash" --arg snapshot "$snapshot_sha" '
        .base_mutation_input_sha256 = $base
        | .mutation_input_sha256 = $current
        | .focused_followup = {
            id: "followup-001",
            reason: "selftest transition",
            changed_file: "src/runner/subprocess.rs",
            baseline_snapshot: "followup-001/base-src-runner-subprocess.rs",
            baseline_snapshot_sha256: $snapshot,
            functions: ["stop_owned_process"],
            selected_mutations: 1,
            caught: 1,
            missed: 0,
            unviable: 0,
            mutation_score_percent: 100
        }
        | .final_outcome.caught = 2
        | .final_outcome.viable = 2
    ' "$evidence/summary.json" > "$summary_backup" || return 1
    mv "$summary_backup" "$evidence/summary.json"
    ROOT_DIR="$fixture" verify_evidence "$evidence" >/dev/null || return 1
    printf '%s\n' '# changed outside declared follow-up' >> "$fixture/tests/probe.rs"
    if ROOT_DIR="$fixture" verify_evidence "$evidence" >/dev/null 2>&1; then
        echo "focused mutation selftest failed: undeclared follow-up input change was accepted" >&2
        return 1
    fi
    printf '%s\n' '#[test] fn probe_is_true() { assert!(true); }' > "$fixture/tests/probe.rs"
    printf '\n' >> "$evidence/followup-001/base-src-runner-subprocess.rs"
    if ROOT_DIR="$fixture" verify_evidence "$evidence" >/dev/null 2>&1; then
        echo "focused mutation selftest failed: changed follow-up snapshot was accepted" >&2
        return 1
    fi
    echo "focused mutation evidence selftest OK"
}

case "${1:-}" in
    --input-hash)
        [ "$#" -le 2 ] || { usage >&2; exit 2; }
        mutation_input_hash "${2:-$ROOT_DIR}"
        ;;
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
