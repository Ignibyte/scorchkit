#!/usr/bin/env bash
set -euo pipefail

repository_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
console_manifest="$repository_root/apps/scorchkit-console/Cargo.toml"
rustal_root="$repository_root/../rustal"
pinned_revision="8b741c4c0e4c87542dea575aea9be9acfa3bf728"

usage() {
    echo "usage: bash bin/console.sh preflight|fmt|check|test|build|run [cargo run args...]" >&2
}

preflight() {
    [ -f "$rustal_root/crates/rustal/Cargo.toml" ] || {
        echo "console preflight failed: sibling Rustal source is unavailable" >&2
        return 1
    }
    local current_revision source_status
    current_revision="$(git -C "$rustal_root" rev-parse HEAD 2>/dev/null)" || {
        echo "console preflight failed: sibling Rustal source is not a Git checkout" >&2
        return 1
    }
    [ "$current_revision" = "$pinned_revision" ] || {
        echo "console preflight failed: sibling Rustal revision does not match the approved pin" >&2
        return 1
    }
    source_status="$(git -C "$rustal_root" status --porcelain --untracked-files=all -- \
        crates/rustal crates/rustal-derive)"
    [ -z "$source_status" ] || {
        echo "console preflight failed: sibling Rustal dependency source is dirty" >&2
        return 1
    }
    echo "console preflight OK: Rustal $pinned_revision"
}

command_name="${1:-}"
case "$command_name" in
    preflight)
        [ "$#" -eq 1 ] || { usage; exit 2; }
        preflight
        ;;
    fmt)
        [ "$#" -eq 1 ] || { usage; exit 2; }
        preflight
        cargo fmt --manifest-path "$console_manifest"
        ;;
    check)
        [ "$#" -eq 1 ] || { usage; exit 2; }
        preflight
        cargo fmt --manifest-path "$console_manifest" -- --check
        cargo clippy --manifest-path "$console_manifest" --locked --all-targets -- -D warnings
        cargo test --manifest-path "$console_manifest" --locked
        ;;
    test)
        [ "$#" -eq 1 ] || { usage; exit 2; }
        preflight
        cargo test --manifest-path "$console_manifest" --locked
        ;;
    build)
        [ "$#" -eq 1 ] || { usage; exit 2; }
        preflight
        cargo build --manifest-path "$console_manifest" --locked
        ;;
    run)
        shift
        preflight
        exec cargo run --manifest-path "$console_manifest" --locked -- "$@"
        ;;
    *)
        usage
        exit 2
        ;;
esac
