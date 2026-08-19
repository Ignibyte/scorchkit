#!/usr/bin/env bash
# Canonical cargo-mutants runner for local delivery checks and scheduled CI.
# Mutation builds are deliberately isolated from the HDD/SMB-backed worktree.

set -uo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT_DIR" || exit 2

MODE="full"
SHARD=""
case "${1:---full}" in
    --diff | diff) MODE="diff" ;;
    --full | full) MODE="full" ;;
    --inspect | inspect) MODE="inspect" ;;
    --selftest | selftest) MODE="selftest" ;;
    --shard | shard)
        MODE="shard"
        SHARD="${2:-}"
        ;;
    *)
        echo "usage: bin/mutants.sh [--diff|--full|--inspect|--selftest|--shard NUM/DEN]" >&2
        exit 2
        ;;
esac

MUTATION_DATABASE_URL=""
if [ "$MODE" != "inspect" ] && [ "$MODE" != "selftest" ]; then
    MUTATION_DATABASE_URL="${SCORCHKIT_MUTATION_DATABASE_URL:-${DATABASE_URL:-}}"
    if [ -z "$MUTATION_DATABASE_URL" ]; then
        echo "database-backed mutation requires SCORCHKIT_MUTATION_DATABASE_URL or DATABASE_URL" >&2
        exit 2
    fi
fi

if [ "$MODE" = "shard" ]; then
    if ! [[ "$SHARD" =~ ^([0-9]+)/([1-9][0-9]*)$ ]]; then
        echo "mutation shard must have the form NUM/DEN" >&2
        exit 2
    fi
    if [ "${BASH_REMATCH[1]}" -ge "${BASH_REMATCH[2]}" ]; then
        echo "mutation shard numerator must be smaller than its denominator" >&2
        exit 2
    fi
fi

need() {
    local command_name="$1"
    local install_hint="$2"
    if command -v "$command_name" >/dev/null 2>&1; then
        return 0
    fi
    echo "missing $command_name; install with: $install_hint" >&2
    return 1
}

need jq "brew install jq (macOS) or apt-get install jq (Linux)" || exit 2

ensure_mutation_outcomes() {
    local mode="$1"
    local status="$2"
    local out_dir="$3"
    local outcomes="$out_dir/outcomes.json"

    if [ -f "$outcomes" ] && jq -e '.outcomes | type == "array"' "$outcomes" >/dev/null 2>&1; then
        return 0
    fi
    if [ "$mode" != "diff" ] || [ "$status" -ne 0 ] || [ -e "$outcomes" ]; then
        return 1
    fi

    # cargo-mutants exits successfully without creating an output directory when
    # changed Rust lines contain no mutation-eligible production code (for example, a
    # test-only edit). Preserve that successful empty result as explicit evidence.
    mkdir -p "$out_dir" || return 1
    jq -n '{success: true, total_mutants: 0, caught: 0, missed: 0, timeout: 0,
        unviable: 0, outcomes: []}' > "$outcomes" || return 1
    printf '[]\n' > "$out_dir/mutants.json" || return 1
    : > "$out_dir/caught.txt"
    : > "$out_dir/missed.txt"
    : > "$out_dir/timeout.txt"
    : > "$out_dir/unviable.txt"
}

mutation_outcomes_selftest() {
    local selftest_root
    selftest_root="$(mktemp -d "${TMPDIR:-/tmp}/scorchkit-mutants-selftest.XXXXXX")" || return 1

    ensure_mutation_outcomes diff 0 "$selftest_root/empty" \
        && jq -e '.success == true and .total_mutants == 0 and .outcomes == []' \
            "$selftest_root/empty/outcomes.json" >/dev/null \
        && [ -f "$selftest_root/empty/mutants.json" ] \
        && [ -f "$selftest_root/empty/caught.txt" ] || {
        rm -rf -- "$selftest_root"
        echo "mutation outcomes selftest failed: successful empty diff was not normalized" >&2
        return 1
    }
    if ensure_mutation_outcomes full 0 "$selftest_root/full" \
        || ensure_mutation_outcomes diff 1 "$selftest_root/failed"; then
        rm -rf -- "$selftest_root"
        echo "mutation outcomes selftest failed: non-success result was normalized" >&2
        return 1
    fi
    mkdir -p "$selftest_root/malformed"
    printf '{"outcomes":"invalid"}\n' > "$selftest_root/malformed/outcomes.json"
    if ensure_mutation_outcomes diff 0 "$selftest_root/malformed"; then
        rm -rf -- "$selftest_root"
        echo "mutation outcomes selftest failed: malformed result was normalized" >&2
        return 1
    fi

    rm -rf -- "$selftest_root"
    echo "mutation outcomes selftest OK"
}

if [ "$MODE" = "selftest" ]; then
    mutation_outcomes_selftest
    exit $?
fi

need cargo-mutants "cargo install cargo-mutants --locked" || exit 2

JOBS="${SCORCHKIT_MUTATION_JOBS:-2}"
if ! [[ "$JOBS" =~ ^[1-9][0-9]*$ ]]; then
    echo "SCORCHKIT_MUTATION_JOBS must be a positive integer" >&2
    exit 2
fi

CPU_TOTAL="$(sysctl -n hw.ncpu 2>/dev/null || getconf _NPROCESSORS_ONLN 2>/dev/null || echo 2)"
if ! [[ "$CPU_TOTAL" =~ ^[1-9][0-9]*$ ]]; then
    CPU_TOTAL=2
fi
DEFAULT_CPU_BUDGET=$((CPU_TOTAL / 2))
if [ "$DEFAULT_CPU_BUDGET" -lt 1 ]; then
    DEFAULT_CPU_BUDGET=1
fi
CPU_BUDGET="${SCORCHKIT_MUTATION_CPU_BUDGET:-$DEFAULT_CPU_BUDGET}"
if ! [[ "$CPU_BUDGET" =~ ^[1-9][0-9]*$ ]]; then
    echo "SCORCHKIT_MUTATION_CPU_BUDGET must be a positive integer" >&2
    exit 2
fi
BUILD_JOBS=$((CPU_BUDGET / JOBS))
if [ "$BUILD_JOBS" -lt 1 ]; then
    BUILD_JOBS=1
fi

# Two clean all-feature build trees can exceed 40 GiB. Operators may raise this
# guard, but lowering it would permit the exact long-running disk exhaustion the
# guard is intended to prevent.
MIN_GIB_PER_WORKER=22
REQUESTED_MIN_GIB="${SCORCHKIT_MUTATION_MIN_GIB_PER_WORKER:-$MIN_GIB_PER_WORKER}"
if ! [[ "$REQUESTED_MIN_GIB" =~ ^[1-9][0-9]*$ ]]; then
    echo "SCORCHKIT_MUTATION_MIN_GIB_PER_WORKER must be a positive integer" >&2
    exit 2
fi
if [ "$REQUESTED_MIN_GIB" -gt "$MIN_GIB_PER_WORKER" ]; then
    MIN_GIB_PER_WORKER="$REQUESTED_MIN_GIB"
fi
HEADROOM_GIB=4
REQUIRED_GIB=$((MIN_GIB_PER_WORKER * JOBS + HEADROOM_GIB))
REQUIRED_BYTES=$((REQUIRED_GIB * 1024 * 1024 * 1024))

available_bytes() {
    df -Pk "$1" 2>/dev/null | awk 'NR == 2 { printf "%.0f", $4 * 1024 }'
}

is_local_scratch() {
    local candidate="$1"
    if [[ "$ROOT_DIR" == /Volumes/* && "$candidate" == /Volumes/* ]]; then
        return 1
    fi
    return 0
}

choose_scratch() {
    local required_bytes="$1"
    local explicit="${SCORCHKIT_MUTATION_SCRATCH:-}"
    local candidate free

    if [ -n "$explicit" ]; then
        mkdir -p "$explicit" || return 1
        if ! is_local_scratch "$explicit"; then
            echo "SCORCHKIT_MUTATION_SCRATCH must not use the /Volumes HDD/SMB mount" >&2
            return 1
        fi
        free="$(available_bytes "$explicit")"
        if [ -z "$free" ] || [ "$free" -lt "$required_bytes" ]; then
            echo "explicit mutation scratch lacks the required ${REQUIRED_GIB} GiB" >&2
            return 1
        fi
        printf '%s\n' "$explicit"
        return 0
    fi

    for candidate in /mnt/buildtmp /dev/shm "${TMPDIR:-}" /tmp; do
        [ -n "$candidate" ] || continue
        candidate="${candidate%/}"
        [ -d "$candidate" ] && [ -w "$candidate" ] || continue
        is_local_scratch "$candidate" || continue
        free="$(available_bytes "$candidate")"
        [ -n "$free" ] || continue
        if [ "$free" -ge "$required_bytes" ]; then
            printf '%s\n' "$candidate"
            return 0
        fi
    done

    echo "no local mutation scratch has the required ${REQUIRED_GIB} GiB free" >&2
    return 1
}

if [ "$MODE" = "inspect" ]; then
    # Inventory generation is bounded and needs no clean build trees.
    REQUIRED_GIB=1
    REQUIRED_BYTES=$((1024 * 1024 * 1024))
fi

SCRATCH_ROOT="$(choose_scratch "$REQUIRED_BYTES")" || exit 2
RUN_ROOT="$(mktemp -d "$SCRATCH_ROOT/scorchkit-mutants-run.XXXXXX")" || exit 2
RUN_TMP="$RUN_ROOT/tmp"
RESULT_PARENT="$RUN_ROOT/results"
mkdir -p "$RUN_TMP" "$RESULT_PARENT" || exit 2

cleanup() {
    if [[ -n "${RUN_ROOT:-}" && "$RUN_ROOT" == "$SCRATCH_ROOT"/scorchkit-mutants-run.* ]]; then
        rm -rf -- "$RUN_ROOT"
    fi
}
trap cleanup EXIT

echo "mutation mode: $MODE${SHARD:+ ($SHARD)}"
echo "mutation scratch: $RUN_ROOT (ephemeral local storage)"
echo "mutation concurrency: $JOBS workers, $BUILD_JOBS build/test threads each"

if [ "$MODE" = "inspect" ]; then
    INVENTORY="$RUN_ROOT/mutants.json"
    if ! TMPDIR="$RUN_TMP" cargo mutants --list --json --workspace --all-features \
        --test-workspace true > "$INVENTORY"; then
        echo "cargo-mutants could not inventory the configured targets" >&2
        exit 1
    fi
    jq -e 'type == "array" and length > 0' "$INVENTORY" >/dev/null || {
        echo "mutation inventory is empty or malformed" >&2
        exit 1
    }
    jq -e 'all(.[];
        ((.file | startswith("src/")) or (.file | test("^crates/[^/]+/src/")))
        and .file != "src/main.rs")' \
        "$INVENTORY" >/dev/null || {
        echo "mutation inventory escaped workspace source roots or included src/main.rs" >&2
        exit 1
    }
    jq -e 'any(.[]; .file == "crates/scorchkit-policy/src/policy.rs")' \
        "$INVENTORY" >/dev/null || {
        echo "mutation inventory does not include the safety policy kernel" >&2
        exit 1
    }
    echo "configured mutants: $(jq 'length' "$INVENTORY")"
    echo "configured source files: $(jq '[.[].file] | unique | length' "$INVENTORY")"
    echo "target checks: workspace sources only, composition binary excluded, policy kernel included"
    exit 0
fi

DIFF_FILE=""
DIFF_SCOPE=""
if [ "$MODE" = "diff" ]; then
    DIFF_FILE="$RUN_ROOT/mutants.diff"
    git diff HEAD -- '*.rs' > "$DIFF_FILE"
    while IFS= read -r source_file; do
        [ -n "$source_file" ] || continue
        git diff --no-index -- /dev/null "$source_file" >> "$DIFF_FILE" || true
    done < <(git ls-files --others --exclude-standard -- '*.rs')

    if [ ! -s "$DIFF_FILE" ]; then
        echo "no changed Rust lines to mutate"
        exit 0
    fi
    DIFF_SCOPE="$({
        git diff --name-only HEAD -- '*.rs'
        git ls-files --others --exclude-standard -- '*.rs'
    } | while IFS= read -r source_file; do
        [ -f "$source_file" ] && printf '%s\n' "$source_file"
    done | sort -u)"
fi

COMMAND=(cargo mutants --workspace --all-features --test-workspace true \
    --jobs "$JOBS" --output "$RESULT_PARENT")
case "$MODE" in
    diff) COMMAND+=(--in-diff "$DIFF_FILE") ;;
    shard) COMMAND+=(--shard "$SHARD") ;;
esac

# cargo-mutants manages a separate target directory for each worker, so a shared
# CARGO_TARGET_DIR defeats that isolation. Database-backed tests use unique rows;
# the database-wide due-schedule fixtures also hold a PostgreSQL advisory lock
# across arrange, act, assert, and cleanup. This keeps the full storage surface in
# mutation scope without sharing generated build trees.
(
    unset CARGO_TARGET_DIR
    export DATABASE_URL="$MUTATION_DATABASE_URL"
    export SCORCHKIT_DATABASE_URL="$MUTATION_DATABASE_URL"
    export TMPDIR="$RUN_TMP"
    export CARGO_BUILD_JOBS="$BUILD_JOBS"
    export RUST_TEST_THREADS="$BUILD_JOBS"
    export NEXTEST_TEST_THREADS="$BUILD_JOBS"
    "${COMMAND[@]}"
)
MUTANTS_STATUS=$?

RUN_COMPLETED=0
case "$MUTANTS_STATUS" in
    0 | 2 | 3) RUN_COMPLETED=1 ;;
esac

OUT_DIR="$RESULT_PARENT/mutants.out"
OUTCOMES="$OUT_DIR/outcomes.json"
if ! ensure_mutation_outcomes "$MODE" "$MUTANTS_STATUS" "$OUT_DIR"; then
    echo "mutation run did not produce valid outcomes" >&2
    exit 1
fi

CAUGHT="$(jq '[.outcomes[] | select(.summary == "CaughtMutant" or .summary == "Timeout")] | length' "$OUTCOMES")"
MISSED="$(jq '[.outcomes[] | select(.summary == "MissedMutant")] | length' "$OUTCOMES")"
TOTAL=$((CAUGHT + MISSED))

if [ "$RUN_COMPLETED" -eq 0 ]; then
    SCORE="null"
elif [ "$TOTAL" -eq 0 ]; then
    if [ "$MODE" = "diff" ]; then
        echo "changed Rust lines generated no viable mutants"
    else
        echo "mutation run generated no viable mutants" >&2
        exit 1
    fi
    SCORE="100"
else
    SCORE="$(jq -n --argjson caught "$CAUGHT" --argjson total "$TOTAL" \
        '$caught * 10000 / $total | floor / 100')"
fi

FLOOR="${SCORCHKIT_MUTATION_MSI_MIN:-95}"
if ! [[ "$FLOOR" =~ ^[0-9]+([.][0-9]+)?$ ]]; then
    echo "SCORCHKIT_MUTATION_MSI_MIN must be numeric" >&2
    exit 2
fi
if jq -e -n --argjson floor "$FLOOR" '$floor < 95' >/dev/null; then
    FLOOR=95
fi

# A green score can still hide a file whose mutants were all unviable, or a
# changed source file that generated none. Report that blind spot separately.
jq -r '[.outcomes[]
        | select((.scenario | type) == "object" and .scenario.Mutant.file != null)
        | {file: .scenario.Mutant.file, viable: (if .summary == "Unviable" then 0 else 1 end)}]
       | group_by(.file)
       | map(select((map(.viable) | add) == 0) | .[0].file)
       | .[]' "$OUTCOMES" > "$OUT_DIR/blind-files.txt"
if [ -n "$DIFF_SCOPE" ]; then
    while IFS= read -r source_file; do
        [ -n "$source_file" ] || continue
        jq -e --arg file "$source_file" \
            '[.outcomes[] | select((.scenario | type) == "object" and .scenario.Mutant.file != null)
              | .scenario.Mutant.file] | index($file)' "$OUTCOMES" >/dev/null \
            || printf '%s\n' "$source_file" >> "$OUT_DIR/blind-files.txt"
    done <<< "$DIFF_SCOPE"
fi
sort -u -o "$OUT_DIR/blind-files.txt" "$OUT_DIR/blind-files.txt"

jq -n \
    --arg mode "$MODE" \
    --arg shard "$SHARD" \
    --argjson completed "$RUN_COMPLETED" \
    --argjson cargo_mutants_status "$MUTANTS_STATUS" \
    --argjson caught "$CAUGHT" \
    --argjson missed "$MISSED" \
    --argjson score "$SCORE" \
    --argjson floor "$FLOOR" \
    '{mode: $mode, shard: $shard, completed: ($completed == 1),
      cargo_mutants_status: $cargo_mutants_status,
      caught: $caught, missed: $missed, viable: ($caught + $missed),
      mutation_score_percent: $score, required_score_percent: $floor}' \
    > "$OUT_DIR/summary.json"

GIT_DIR="$(git rev-parse --absolute-git-dir)"
EVIDENCE_DIR="$GIT_DIR/scorchkit-mutants-last"
if [[ "$EVIDENCE_DIR" != "$GIT_DIR"/scorchkit-mutants-last ]]; then
    echo "refusing an unexpected mutation evidence path" >&2
    exit 2
fi
rm -rf -- "$EVIDENCE_DIR"
mkdir -p "$EVIDENCE_DIR" || exit 2
for artifact in summary.json outcomes.json mutants.json caught.txt missed.txt timeout.txt unviable.txt blind-files.txt; do
    [ -f "$OUT_DIR/$artifact" ] && cp -p "$OUT_DIR/$artifact" "$EVIDENCE_DIR/$artifact"
done

echo "mutation evidence: $EVIDENCE_DIR"
if [ "$RUN_COMPLETED" -eq 0 ]; then
    echo "cargo-mutants failed before producing a completed result (exit $MUTANTS_STATUS)" >&2
    exit 1
fi

echo "mutation score: ${SCORE}% ($CAUGHT caught, $MISSED missed; floor ${FLOOR}%)"
if [ -s "$OUT_DIR/blind-files.txt" ]; then
    echo "mutation-blind source files:"
    sed 's/^/  /' "$OUT_DIR/blind-files.txt"
fi

if ! jq -e -n --argjson score "$SCORE" --argjson floor "$FLOOR" \
    '$score >= $floor' >/dev/null; then
    echo "mutation score is below the required floor" >&2
    exit 1
fi
