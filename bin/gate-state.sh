#!/usr/bin/env bash
# Shared worktree fingerprint used by the delivery gate and pre-commit hook.

SCORCHKIT_PROJECT_ROOT="${SCORCHKIT_PROJECT_ROOT:-$(git rev-parse --show-toplevel 2>/dev/null || pwd)}"
SCORCHKIT_GIT_DIR="$(git -C "$SCORCHKIT_PROJECT_ROOT" rev-parse --absolute-git-dir 2>/dev/null || true)"
SCORCHKIT_GIT_DIR="${SCORCHKIT_GIT_DIR:-$SCORCHKIT_PROJECT_ROOT/.git}"
SCORCHKIT_GATE_RECEIPT="${SCORCHKIT_GATE_RECEIPT:-$SCORCHKIT_GIT_DIR/scorchkit-gate-receipt}"

scorchkit_gate_state_hash() {
    local root="$SCORCHKIT_PROJECT_ROOT"
    local digest entry_count=0 file file_list fingerprint head manifest state_failed=0 target

    if ! command -v shasum >/dev/null 2>&1 || ! command -v mktemp >/dev/null 2>&1; then
        printf 'hash-tool-missing-%s\n' "$$"
        return 0
    fi

    file_list="$(mktemp "${TMPDIR:-/tmp}/scorchkit-gate-files.XXXXXX")" || {
        printf 'hash-read-failed-%s\n' "$$"
        return 0
    }
    manifest="$(mktemp "${TMPDIR:-/tmp}/scorchkit-gate-manifest.XXXXXX")" || {
        rm -f "$file_list"
        printf 'hash-read-failed-%s\n' "$$"
        return 0
    }

    if ! {
        cd "$root" 2>/dev/null && {
            git ls-files -z -- . 2>/dev/null
            git ls-files -z --others --exclude-standard -- . 2>/dev/null
            git diff --cached --name-only --diff-filter=D -z -- . 2>/dev/null
        } | LC_ALL=C sort -z -u > "$file_list"
    }; then
        rm -f "$file_list" "$manifest"
        printf 'hash-read-failed-%s\n' "$$"
        return 0
    fi

    head="$(git -C "$root" rev-parse HEAD 2>/dev/null || printf 'no-head')"
    printf 'HEAD\0%s\0' "$head" > "$manifest"
    while IFS= read -r -d '' file; do
        if [ -L "$root/$file" ]; then
            target="$(readlink "$root/$file" 2>/dev/null)" || {
                state_failed=1
                break
            }
            printf 'PATH\0%s\0SYMLINK\0%s\0' "$file" "$target" >> "$manifest"
        elif [ -f "$root/$file" ]; then
            digest="$(shasum -a 256 < "$root/$file" 2>/dev/null | awk '{print $1}')"
            [ -n "$digest" ] || {
                state_failed=1
                break
            }
            printf 'PATH\0%s\0FILE\0%s\0' "$file" "$digest" >> "$manifest"
        else
            continue
        fi
        entry_count=$((entry_count + 1))
    done < "$file_list"
    rm -f "$file_list"

    if [ "$state_failed" -ne 0 ]; then
        rm -f "$manifest"
        printf 'hash-read-failed-%s\n' "$$"
        return 0
    fi

    if [ "$entry_count" -eq 0 ]; then
        rm -f "$manifest"
        printf 'hash-empty-%s\n' "$$"
        return 0
    fi

    fingerprint="$(shasum -a 256 < "$manifest" 2>/dev/null | awk '{print $1}')"
    rm -f "$manifest"
    if [ -z "$fingerprint" ]; then
        printf 'hash-read-failed-%s\n' "$$"
    else
        printf '%s\n' "$fingerprint"
    fi
}

scorchkit_focused_evidence_verifier() {
    local evidence_dir="$1" mode
    [ -f "$evidence_dir/summary.json" ] && [ ! -L "$evidence_dir/summary.json" ] || return 1
    mode="$(jq -r '.mode // empty' "$evidence_dir/summary.json" 2>/dev/null)" || return 1
    case "$mode" in
        focused_repaired_functions)
            printf '%s\n' "$SCORCHKIT_PROJECT_ROOT/bin/focused-mutation-evidence.sh"
            ;;
        sealed_green_diff | sealed_green_scope)
            printf '%s\n' "$SCORCHKIT_PROJECT_ROOT/bin/sealed-mutation-baseline.sh"
            ;;
        focused_changed_files)
            [ "$(jq -r '.ticket // empty' "$evidence_dir/summary.json")" = "TICKET-002" ] \
                || return 1
            printf '%s\n' "$SCORCHKIT_PROJECT_ROOT/bin/ticket-002-mutation-evidence.sh"
            ;;
        *) return 1 ;;
    esac
}

scorchkit_verify_focused_evidence() {
    local evidence_dir="$1" verifier
    verifier="$(scorchkit_focused_evidence_verifier "$evidence_dir")" || return 1
    [ -f "$verifier" ] || return 1
    bash "$verifier" --verify "$evidence_dir"
}

scorchkit_focused_evidence_digest() {
    local evidence_dir="$1" verifier
    verifier="$(scorchkit_focused_evidence_verifier "$evidence_dir")" || return 1
    [ -f "$verifier" ] || return 1
    bash "$verifier" --digest "$evidence_dir"
}

scorchkit_write_gate_receipt() {
    local evidence_digest="${SCORCHKIT_GATE_EVIDENCE_DIGEST:-}"
    local evidence_name="${SCORCHKIT_GATE_EVIDENCE_NAME:-}"
    local fingerprint mode="${SCORCHKIT_GATE_MODE:-}" temporary verifier

    case "$mode" in
        diff | full)
            if [ -n "$evidence_name" ] || [ -n "$evidence_digest" ]; then
                echo "delivery receipt was not written: $mode mode cannot carry focused evidence" >&2
                return 1
            fi
            ;;
        focused-repair)
            if ! [[ "$evidence_name" =~ ^scorchkit-mutants-focused-[A-Za-z0-9][A-Za-z0-9._-]*$ ]]; then
                echo "delivery receipt was not written: invalid focused evidence name" >&2
                return 1
            fi
            verifier="$(scorchkit_focused_evidence_verifier \
                "$SCORCHKIT_GIT_DIR/$evidence_name")" || {
                echo "delivery receipt was not written: focused evidence verifier is missing" >&2
                return 1
            }
            scorchkit_verify_focused_evidence "$SCORCHKIT_GIT_DIR/$evidence_name" >/dev/null || {
                echo "delivery receipt was not written: focused evidence verification failed" >&2
                return 1
            }
            fingerprint="$(scorchkit_focused_evidence_digest \
                "$SCORCHKIT_GIT_DIR/$evidence_name")" || return 1
            if [ -n "$evidence_digest" ] && [ "$evidence_digest" != "$fingerprint" ]; then
                echo "delivery receipt was not written: focused evidence changed during the gate" >&2
                return 1
            fi
            evidence_digest="$fingerprint"
            ;;
        *)
            echo "delivery receipt was not written: gate mode must be diff, full, or focused-repair" >&2
            return 1
            ;;
    esac

    fingerprint="$(scorchkit_gate_state_hash)"
    case "$fingerprint" in
        "" | hash-*)
            echo "delivery receipt was not written: worktree fingerprint failed" >&2
            return 1
            ;;
    esac
    temporary="$(mktemp "$SCORCHKIT_GATE_RECEIPT.XXXXXX")" || {
        echo "delivery receipt was not written: could not create a temporary receipt" >&2
        return 1
    }
    if ! {
        printf 'version=2\n'
        printf 'worktree_sha256=%s\n' "$fingerprint"
        printf 'mode=%s\n' "$mode"
        printf 'evidence_name=%s\n' "$evidence_name"
        printf 'evidence_sha256=%s\n' "$evidence_digest"
    } > "$temporary"; then
        rm -f "$temporary"
        return 1
    fi
    mv "$temporary" "$SCORCHKIT_GATE_RECEIPT"
}

scorchkit_gate_receipt_value() {
    local key="$1"
    awk -v key="$key" '
        index($0, key "=") == 1 {
            count++
            value = substr($0, length(key) + 2)
        }
        END {
            if (count != 1) exit 1
            print value
        }
    ' "$SCORCHKIT_GATE_RECEIPT"
}

scorchkit_gate_receipt_mode() {
    [ -f "$SCORCHKIT_GATE_RECEIPT" ] && [ ! -L "$SCORCHKIT_GATE_RECEIPT" ] || return 1
    scorchkit_gate_receipt_value mode
}

scorchkit_verify_gate_receipt() {
    local actual actual_evidence evidence_digest evidence_name expected mode version verifier
    [ -f "$SCORCHKIT_GATE_RECEIPT" ] && [ ! -L "$SCORCHKIT_GATE_RECEIPT" ] || return 1
    [ "$(wc -l < "$SCORCHKIT_GATE_RECEIPT" | tr -d '[:space:]')" = "5" ] || return 1
    if grep -Ev '^(version|worktree_sha256|mode|evidence_name|evidence_sha256)=' \
        "$SCORCHKIT_GATE_RECEIPT" | grep -q .; then
        return 1
    fi
    version="$(scorchkit_gate_receipt_value version)" || return 1
    expected="$(scorchkit_gate_receipt_value worktree_sha256)" || return 1
    mode="$(scorchkit_gate_receipt_value mode)" || return 1
    evidence_name="$(scorchkit_gate_receipt_value evidence_name)" || return 1
    evidence_digest="$(scorchkit_gate_receipt_value evidence_sha256)" || return 1
    [ "$version" = "2" ] || return 1
    [[ "$expected" =~ ^[0-9a-f]{64}$ ]] || return 1
    actual="$(scorchkit_gate_state_hash)"
    [ "$expected" = "$actual" ] || return 1

    case "$mode" in
        diff | full)
            [ -z "$evidence_name" ] && [ -z "$evidence_digest" ]
            ;;
        focused-repair)
            [[ "$evidence_name" =~ ^scorchkit-mutants-focused-[A-Za-z0-9][A-Za-z0-9._-]*$ ]] \
                && [[ "$evidence_digest" =~ ^[0-9a-f]{64}$ ]] || return 1
            verifier="$(scorchkit_focused_evidence_verifier \
                "$SCORCHKIT_GIT_DIR/$evidence_name")" || return 1
            [ -f "$verifier" ] || return 1
            scorchkit_verify_focused_evidence "$SCORCHKIT_GIT_DIR/$evidence_name" >/dev/null \
                || return 1
            actual_evidence="$(scorchkit_focused_evidence_digest \
                "$SCORCHKIT_GIT_DIR/$evidence_name")" \
                || return 1
            [ "$actual_evidence" = "$evidence_digest" ]
            ;;
        *) return 1 ;;
    esac
}
