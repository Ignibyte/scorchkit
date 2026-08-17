#!/usr/bin/env bash
# Derive every supported feature state from Cargo.toml for gate:2.

set -uo pipefail

extract_features() {
    awk '
        /^\[features\][[:space:]]*$/ { in_features = 1; next }
        /^\[/ { in_features = 0 }
        in_features && /^[A-Za-z0-9_-]+[[:space:]]*=/ {
            key = $0
            sub(/[[:space:]]*=.*/, "", key)
            if (key != "default") print key
        }
    ' "$1" | LC_ALL=C sort -u
}

selftest() {
    local fixture actual expected
    fixture="$(mktemp /tmp/scorchkit-feature-states.XXXXXX)" || return 1
    FEATURE_STATE_FIXTURE="$fixture"
    trap 'rm -f "${FEATURE_STATE_FIXTURE:-}"' EXIT
    printf '%s\n' \
        '[package]' \
        'name = "fixture"' \
        '[features]' \
        'default = ["alpha"]' \
        'zeta = []' \
        'alpha = []' \
        '[dependencies]' > "$fixture"
    actual="$(extract_features "$fixture")"
    expected="$(printf '%s\n' alpha zeta)"
    [ "$actual" = "$expected" ] || {
        echo "feature-state selftest failed: derived feature names differ" >&2
        return 1
    }
    echo "feature-state selftest OK"
}

if [ "${1:-}" = "--selftest" ]; then
    selftest
    exit $?
fi

ROOT_DIR="${1:-$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)}"
MANIFEST="$ROOT_DIR/Cargo.toml"
[ -f "$MANIFEST" ] || {
    echo "feature-state derivation failed: $MANIFEST is missing" >&2
    exit 1
}

printf '%s\n' '<default>' '--all-features'
while IFS= read -r feature; do
    [ -n "$feature" ] || continue
    printf '%s\n' "--no-default-features --features $feature"
done < <(extract_features "$MANIFEST")
