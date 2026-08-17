#!/usr/bin/env bash
# Verify the owner-approved SK-028 focused-change evidence without running mutants.

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
    initial/baseline.log.gz
    recheck/outcomes.json
    recheck/mutants.json
    recheck/caught.txt
    recheck/missed.txt
    recheck/timeout.txt
    recheck/unviable.txt
    recheck/cancellation.log.gz
    recheck/phased-dast.log.gz
    transition/base-src-runner-job_executor.rs
    transition/base-src-runner-orchestrator.rs
)
readonly EVIDENCE_FILES

usage() {
    cat <<'USAGE'
usage: bin/ticket-002-mutation-evidence.sh COMMAND [ARGS]

  --input-hash [ROOT] [REPOSITORY_PATH SNAPSHOT]...
  --verify EVIDENCE_DIR
  --digest EVIDENCE_DIR
USAGE
}

need_tool() {
    local tool="$1"
    command -v "$tool" >/dev/null 2>&1 || {
        echo "TICKET-002 mutation evidence requires $tool" >&2
        return 1
    }
}

mutation_input_hash() {
    local root="${1:-$ROOT_DIR}"
    shift || true
    local digest entry_count=0 file file_list fingerprint head index manifest
    local override_count=0 override_seen=0 state_failed=0 target
    local -a override_paths=() override_sources=()
    local -a scope=(
        Cargo.toml
        Cargo.lock
        rust-toolchain
        rust-toolchain.toml
        build.rs
        .cargo
        .config/nextest.toml
        crates
        src
        tests
        examples
        migrations
        rules
    )

    need_tool git || return 1
    need_tool mktemp || return 1
    need_tool shasum || return 1
    [ "$(( $# % 2 ))" -eq 0 ] || {
        echo "mutation input overrides require path/snapshot pairs" >&2
        return 1
    }
    while [ "$#" -gt 0 ]; do
        case "$1" in
            "" | /* | ../* | */../* | */..)
                echo "mutation input override path is invalid: $1" >&2
                return 1
                ;;
        esac
        [ -f "$2" ] && [ ! -L "$2" ] || {
            echo "mutation input override is missing or is a symlink: $2" >&2
            return 1
        }
        for index in "${!override_paths[@]}"; do
            [ "${override_paths[$index]}" != "$1" ] || {
                echo "mutation input override path is duplicated: $1" >&2
                return 1
            }
        done
        override_paths+=("$1")
        override_sources+=("$2")
        shift 2
    done
    override_count="${#override_paths[@]}"

    git -C "$root" rev-parse --show-toplevel >/dev/null 2>&1 || {
        echo "mutation input root is not a Git worktree: $root" >&2
        return 1
    }
    root="$(git -C "$root" rev-parse --show-toplevel 2>/dev/null)" || return 1
    file_list="$(mktemp "${TMPDIR:-/tmp}/scorchkit-ticket-002-inputs.XXXXXX")" || return 1
    manifest="$(mktemp "${TMPDIR:-/tmp}/scorchkit-ticket-002-manifest.XXXXXX")" || {
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
            digest=""
            for index in "${!override_paths[@]}"; do
                if [ "$file" = "${override_paths[$index]}" ]; then
                    digest="$(shasum -a 256 < "${override_sources[$index]}" | awk '{print $1}')"
                    override_seen=$((override_seen + 1))
                    break
                fi
            done
            if [ -z "$digest" ]; then
                digest="$(shasum -a 256 < "$root/$file" | awk '{print $1}')"
            fi
            [[ "$digest" =~ ^[0-9a-f]{64}$ ]] || {
                state_failed=1
                break
            }
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
        || [ "$override_seen" -ne "$override_count" ]; then
        rm -f "$manifest"
        echo "could not read a complete mutation input inventory" >&2
        return 1
    fi
    fingerprint="$(shasum -a 256 < "$manifest" | awk '{print $1}')"
    rm -f "$manifest"
    [[ "$fingerprint" =~ ^[0-9a-f]{64}$ ]] || return 1
    printf '%s\n' "$fingerprint"
}

evidence_files_exist() {
    local evidence="$1" relative
    [ -d "$evidence" ] && [ ! -L "$evidence" ] || {
        echo "TICKET-002 mutation evidence directory is missing: $evidence" >&2
        return 1
    }
    for relative in "${EVIDENCE_FILES[@]}"; do
        if [ ! -f "$evidence/$relative" ] || [ -L "$evidence/$relative" ]; then
            echo "TICKET-002 mutation evidence is missing or is a symlink: $relative" >&2
            return 1
        fi
    done
}

evidence_digest() {
    local evidence="$1" digest manifest relative result
    need_tool mktemp || return 1
    need_tool shasum || return 1
    evidence_files_exist "$evidence" || return 1
    manifest="$(mktemp "${TMPDIR:-/tmp}/scorchkit-ticket-002-evidence.XXXXXX")" || return 1
    : > "$manifest"
    for relative in "${EVIDENCE_FILES[@]}"; do
        digest="$(shasum -a 256 < "$evidence/$relative" | awk '{print $1}')"
        [[ "$digest" =~ ^[0-9a-f]{64}$ ]] || {
            rm -f "$manifest"
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
    actual="$(mktemp "${TMPDIR:-/tmp}/scorchkit-ticket-002-outcomes.XXXXXX")" || return 1
    expected="$(mktemp "${TMPDIR:-/tmp}/scorchkit-ticket-002-names.XXXXXX")" || {
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
        echo "TICKET-002 outcome list does not match raw outcomes: $names" >&2
        return 1
    fi
    rm -f "$actual" "$expected"
}

current_inventory_matches() {
    local expected="$1" actual canonical candidate
    need_tool cargo || return 1
    actual="$(mktemp "${TMPDIR:-/tmp}/scorchkit-ticket-002-current.XXXXXX")" || return 1
    canonical="$(mktemp "${TMPDIR:-/tmp}/scorchkit-ticket-002-canonical.XXXXXX")" || {
        rm -f "$actual"
        return 1
    }
    candidate="$(mktemp "${TMPDIR:-/tmp}/scorchkit-ticket-002-candidate.XXXXXX")" || {
        rm -f "$actual" "$canonical"
        return 1
    }
    if ! cargo mutants --list --json --all-features \
        --file src/runner/job_executor.rs \
        --file src/runner/orchestrator.rs \
        --file src/runner/code_orchestrator.rs \
        --file src/runner/infra_orchestrator.rs \
        --file src/runner/cloud_orchestrator.rs > "$candidate"; then
        rm -f "$actual" "$canonical" "$candidate"
        echo "could not inventory current SK-028 mutants" >&2
        return 1
    fi
    jq -S 'sort_by(.name)' "$expected" > "$canonical" || {
        rm -f "$actual" "$canonical" "$candidate"
        return 1
    }
    jq -S --slurpfile expected "$expected" '
        [.[] | . as $candidate
            | select(any($expected[0][]; .name == $candidate.name))]
        | sort_by(.name)
    ' "$candidate" > "$actual" || {
        rm -f "$actual" "$canonical" "$candidate"
        return 1
    }
    if ! cmp -s "$canonical" "$actual"; then
        rm -f "$actual" "$canonical" "$candidate"
        echo "current SK-028 mutation inventory differs from the sealed initial inventory" >&2
        return 1
    fi
    rm -f "$actual" "$canonical" "$candidate"
}

verify_evidence() {
    local evidence="$1" summary initial_outcomes initial_mutants recheck_outcomes recheck_mutants
    local base_job base_orchestrator base_hash current_hash inventory_a inventory_b missed_names
    local snapshot_hash result_digest

    need_tool cmp || return 1
    need_tool gzip || return 1
    need_tool jq || return 1
    evidence_files_exist "$evidence" || return 1
    summary="$evidence/summary.json"
    initial_outcomes="$evidence/initial/outcomes.json"
    initial_mutants="$evidence/initial/mutants.json"
    recheck_outcomes="$evidence/recheck/outcomes.json"
    recheck_mutants="$evidence/recheck/mutants.json"
    base_job="$evidence/transition/base-src-runner-job_executor.rs"
    base_orchestrator="$evidence/transition/base-src-runner-orchestrator.rs"

    if ! jq -e '
        .ticket == "TICKET-002"
        and .roadmap_item == "SK-028"
        and .mode == "focused_changed_files"
        and .completed == true
        and .date == "2026-08-16"
        and .cargo_mutants_version == "27.1.0"
        and .owner_approval == "mutate_only_fixed_scope_full_run_deferred"
        and .full_repository_mutation == "deferred_by_repository_owner"
        and (.base_mutation_input_sha256 | test("^[0-9a-f]{64}$"))
        and (.mutation_input_sha256 | test("^[0-9a-f]{64}$"))
        and .scope.files == [
            "src/runner/cloud_orchestrator.rs",
            "src/runner/code_orchestrator.rs",
            "src/runner/infra_orchestrator.rs",
            "src/runner/job_executor.rs",
            "src/runner/orchestrator.rs"
        ]
        and .scope.functions == 35
        and .scope.selected_mutations == 68
        and .initial_run == {caught: 31, timeouts: 2, missed: 2, unviable: 33}
        and .exact_recheck == {
            selected_mutations: 2, caught: 2, timeouts: 0, missed: 0, unviable: 0,
            baseline: "skipped_after_green_initial"
        }
        and .final_outcome == {
            caught: 35, missed: 0, unviable: 33, viable: 35,
            mutation_score_percent: 100, required_score_percent: 95
        }
        and .input_transition.snapshots == [
            {
                file: "src/runner/job_executor.rs",
                snapshot: "transition/base-src-runner-job_executor.rs",
                sha256: .input_transition.snapshots[0].sha256
            },
            {
                file: "src/runner/orchestrator.rs",
                snapshot: "transition/base-src-runner-orchestrator.rs",
                sha256: .input_transition.snapshots[1].sha256
            }
        ]
        and all(.input_transition.snapshots[].sha256; test("^[0-9a-f]{64}$"))
    ' "$summary" >/dev/null; then
        echo "TICKET-002 mutation summary has an invalid contract" >&2
        return 1
    fi

    if ! jq -e 'type == "array" and length == 68
            and ([.[].name] | length == (unique | length))
            and all(.[]; (.name | type == "string" and length > 0)
                and (.file | type == "string" and length > 0)
                and (.function.function_name | type == "string" and length > 0))' \
        "$initial_mutants" >/dev/null \
        || ! jq -e 'type == "array" and length == 2
            and ([.[].name] | length == (unique | length))
            and all(.[]; (.name | type == "string" and length > 0)
                and (.file | type == "string" and length > 0)
                and (.function.function_name | type == "string" and length > 0))' \
        "$recheck_mutants" >/dev/null; then
        echo "TICKET-002 mutation inventory JSON is invalid" >&2
        return 1
    fi
    if ! jq -e '
        .cargo_mutants_version == "27.1.0"
        and .total_mutants == 68 and .caught == 31 and .missed == 2
        and .unviable == 33 and .timeout == 2 and (.outcomes | length == 69)
        and ([.outcomes[] | select(.scenario == "Baseline" and .summary == "Success")]
            | length == 1)
        and ([.outcomes[] | select(.summary == "CaughtMutant")] | length == 31)
        and ([.outcomes[] | select(.summary == "Timeout")] | length == 2)
        and ([.outcomes[] | select(.summary == "MissedMutant")] | length == 2)
        and ([.outcomes[] | select(.summary == "Unviable")] | length == 33)
    ' "$initial_outcomes" >/dev/null \
        || ! jq -e '
            .cargo_mutants_version == "27.1.0"
            and .total_mutants == 2 and .caught == 2 and .missed == 0
            and .unviable == 0 and .timeout == 0 and (.outcomes | length == 2)
            and ([.outcomes[] | select(.summary == "CaughtMutant")] | length == 2)
            and ([.outcomes[] | select(.scenario == "Baseline")] | length == 0)
        ' "$recheck_outcomes" >/dev/null; then
        echo "TICKET-002 raw mutation outcomes do not match the sealed summary" >&2
        return 1
    fi

    compare_outcome_names "$initial_outcomes" CaughtMutant "$evidence/initial/caught.txt" || return 1
    compare_outcome_names "$initial_outcomes" MissedMutant "$evidence/initial/missed.txt" || return 1
    compare_outcome_names "$initial_outcomes" Timeout "$evidence/initial/timeout.txt" || return 1
    compare_outcome_names "$initial_outcomes" Unviable "$evidence/initial/unviable.txt" || return 1
    compare_outcome_names "$recheck_outcomes" CaughtMutant "$evidence/recheck/caught.txt" || return 1
    compare_outcome_names "$recheck_outcomes" MissedMutant "$evidence/recheck/missed.txt" || return 1
    compare_outcome_names "$recheck_outcomes" Timeout "$evidence/recheck/timeout.txt" || return 1
    compare_outcome_names "$recheck_outcomes" Unviable "$evidence/recheck/unviable.txt" || return 1

    inventory_a="$(mktemp "${TMPDIR:-/tmp}/scorchkit-ticket-002-inventory-a.XXXXXX")" || return 1
    inventory_b="$(mktemp "${TMPDIR:-/tmp}/scorchkit-ticket-002-inventory-b.XXXXXX")" || {
        rm -f "$inventory_a"
        return 1
    }
    missed_names="$(mktemp "${TMPDIR:-/tmp}/scorchkit-ticket-002-missed.XXXXXX")" || {
        rm -f "$inventory_a" "$inventory_b"
        return 1
    }
    jq -r '.[].name' "$initial_mutants" | LC_ALL=C sort > "$inventory_a"
    jq -r '.outcomes[] | select(.scenario | type == "object") | .scenario.Mutant.name' \
        "$initial_outcomes" | LC_ALL=C sort > "$inventory_b"
    if ! cmp -s "$inventory_a" "$inventory_b"; then
        rm -f "$inventory_a" "$inventory_b" "$missed_names"
        echo "initial inventory does not match the complete raw outcome set" >&2
        return 1
    fi
    jq -r '.outcomes[] | select(.summary == "MissedMutant") | .scenario.Mutant.name' \
        "$initial_outcomes" | LC_ALL=C sort > "$missed_names"
    jq -r '.[].name' "$recheck_mutants" | LC_ALL=C sort > "$inventory_a"
    jq -r '.outcomes[] | select(.summary == "CaughtMutant") | .scenario.Mutant.name' \
        "$recheck_outcomes" | LC_ALL=C sort > "$inventory_b"
    if ! cmp -s "$missed_names" "$inventory_a" || ! cmp -s "$missed_names" "$inventory_b"; then
        rm -f "$inventory_a" "$inventory_b" "$missed_names"
        echo "exact recheck does not match the complete initial survivor set" >&2
        return 1
    fi
    jq -r '[.[].file] | unique[]' "$initial_mutants" | LC_ALL=C sort > "$inventory_a"
    jq -r '.scope.files[]' "$summary" | LC_ALL=C sort > "$inventory_b"
    if ! cmp -s "$inventory_a" "$inventory_b" \
        || [ "$(jq -r '[.[].function.function_name] | unique | length' "$initial_mutants")" -ne 35 ]; then
        rm -f "$inventory_a" "$inventory_b" "$missed_names"
        echo "TICKET-002 file or function scope differs from the approved scope" >&2
        return 1
    fi
    rm -f "$inventory_a" "$inventory_b" "$missed_names"

    if gzip -cd "$evidence/initial/baseline.log.gz" \
        | grep -Fq 'final_cancellation_check_rejects_a_cancelled_token' \
        || gzip -cd "$evidence/initial/baseline.log.gz" \
        | grep -Fq 'explicit_phased_dast_run_finishes_recon_before_scanner_consumers' \
        || ! gzip -cd "$evidence/initial/baseline.log.gz" \
        | grep -Fq 'test result: ok. 1219 passed; 0 failed; 4 ignored'; then
        echo "initial baseline log does not prove the pre-repair test inventory" >&2
        return 1
    fi
    if ! gzip -cd "$evidence/recheck/cancellation.log.gz" \
        | grep -Fq 'final_cancellation_check_rejects_a_cancelled_token ... FAILED' \
        || ! gzip -cd "$evidence/recheck/phased-dast.log.gz" \
        | grep -Fq 'explicit_phased_dast_run_finishes_recon_before_scanner_consumers ... FAILED'; then
        echo "recheck logs do not prove the two repaired survivor tests" >&2
        return 1
    fi

    snapshot_hash="$(shasum -a 256 < "$base_job" | awk '{print $1}')"
    [ "$snapshot_hash" = "$(jq -r '.input_transition.snapshots[0].sha256' "$summary")" ] || {
        echo "job executor transition snapshot digest is invalid" >&2
        return 1
    }
    snapshot_hash="$(shasum -a 256 < "$base_orchestrator" | awk '{print $1}')"
    [ "$snapshot_hash" = "$(jq -r '.input_transition.snapshots[1].sha256' "$summary")" ] || {
        echo "orchestrator transition snapshot digest is invalid" >&2
        return 1
    }
    if cmp -s "$ROOT_DIR/src/runner/job_executor.rs" "$base_job" \
        || cmp -s "$ROOT_DIR/src/runner/orchestrator.rs" "$base_orchestrator"; then
        echo "TICKET-002 transition snapshots must differ from the repaired sources" >&2
        return 1
    fi

    current_hash="$(mutation_input_hash "$ROOT_DIR")" || return 1
    [ "$current_hash" = "$(jq -r '.mutation_input_sha256' "$summary")" ] || {
        echo "TICKET-002 evidence does not match current mutation inputs" >&2
        return 1
    }
    base_hash="$(mutation_input_hash "$ROOT_DIR" \
        src/runner/job_executor.rs "$base_job" \
        src/runner/orchestrator.rs "$base_orchestrator")" || return 1
    [ "$base_hash" = "$(jq -r '.base_mutation_input_sha256' "$summary")" ] || {
        echo "TICKET-002 transition changes mutation inputs outside the two sealed snapshots" >&2
        return 1
    }
    current_inventory_matches "$initial_mutants" || return 1

    result_digest="$(evidence_digest "$evidence")" || return 1
    echo "TICKET-002 focused evidence verified: 35/35 viable caught, 100% MSI"
    echo "mutation input: $current_hash"
    echo "evidence digest: $result_digest"
}

case "${1:-}" in
    --input-hash)
        [ "$#" -ge 1 ] || { usage >&2; exit 2; }
        shift
        mutation_input_hash "${1:-$ROOT_DIR}" "${@:2}"
        ;;
    --verify)
        [ "$#" -eq 2 ] || { usage >&2; exit 2; }
        verify_evidence "$2"
        ;;
    --digest)
        [ "$#" -eq 2 ] || { usage >&2; exit 2; }
        evidence_digest "$2"
        ;;
    *)
        usage >&2
        exit 2
        ;;
esac
