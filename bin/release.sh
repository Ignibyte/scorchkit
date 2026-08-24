#!/usr/bin/env bash
# Reproducible release qualification, evidence assembly, and Sigstore verification.

set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
POLICY_FILE="$ROOT_DIR/release/policy.json"
MANIFEST_NAME="scorchkit-release-manifest.json"
PROVENANCE_NAME="scorchkit-provenance.intoto.json"
CHECKSUM_NAME="SHA256SUMS"

usage() {
    cat <<'USAGE'
usage: bin/release.sh COMMAND [ARGS]

commands:
  preflight TAG REVISION [SOURCE_ROOT]
  build TARGET SOURCE_A SOURCE_B OUTPUT_DIR
  install-tools OUTPUT_DIR
  assemble STAGE_DIR TAG REVISION [REPOSITORY] [SOURCE_DATE_EPOCH]
  verify STAGE_DIR
  subjects STAGE_DIR
  sign STAGE_DIR IDENTITY REVISION
  verify-signatures STAGE_DIR IDENTITY REVISION
  verify-signature-negatives STAGE_DIR IDENTITY REVISION
  --selftest
USAGE
}

fail() {
    echo "release qualification failed: $*" >&2
    return 1
}

need() {
    command -v "$1" >/dev/null 2>&1 || fail "missing required command: $1"
}

sha256_file() {
    local path="$1"
    if command -v sha256sum >/dev/null 2>&1; then
        sha256sum -- "$path" | awk '{print $1}'
    elif command -v shasum >/dev/null 2>&1; then
        shasum -a 256 -- "$path" | awk '{print $1}'
    else
        fail "no SHA-256 implementation is available"
    fi
}

file_size() {
    wc -c < "$1" | tr -d '[:space:]'
}

make_release_temp() {
    local base="${1:-${RUNNER_TEMP:-${TMPDIR:-/tmp}}}"
    local path
    mkdir -p "$base"
    path="$(mktemp -d "$base/scorchkit-release.XXXXXX")"
    : > "$path/.scorchkit-release-temp"
    printf '%s\n' "$path"
}

remove_release_temp() {
    local path="$1"
    [ -n "$path" ] && [ "$path" != "/" ] && [ -f "$path/.scorchkit-release-temp" ] \
        || fail "refusing to remove an unowned temporary directory: $path"
    rm -rf -- "$path"
}

policy() {
    jq -er "$1" "$POLICY_FILE"
}

validate_policy() {
    need jq
    [ -f "$POLICY_FILE" ] || fail "release policy is missing"
    jq -e '
        .schema == "scorchkit.release-policy/v1"
        and .package == "scorchkit"
        and (.repository | test("^[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+$"))
        and .workflow == ".github/workflows/release.yml"
        and (.toolchain | test("^[0-9]+\\.[0-9]+\\.[0-9]+$"))
        and .features == ["infra", "cloud", "mcp"]
        and (.targets | length == 4)
        and ((.targets | map(.target) | unique | length) == 4)
        and ((.targets | map(.asset) | unique | length) == 4)
        and (.targets | all(
            (.target | type == "string" and length > 0)
            and (.runner | type == "string" and length > 0)
            and (.asset | test("^scorchkit-[A-Za-z0-9_.-]+$"))
        ))
        and .budgets.binary_bytes == 157286400
        and .budgets.startup_seconds == 2
        and .budgets.termination_seconds == 2
        and .budgets.workflow_minutes == 45
        and .tools.syft.version == "1.50.0"
        and (.tools.syft.sha256 | test("^[0-9a-f]{64}$"))
        and .tools.cosign.version == "3.1.2"
        and (.tools.cosign.sha256 | test("^[0-9a-f]{64}$"))
        and (.tools.sigstore_trusted_root.version | startswith("root-signing@"))
        and (.tools.sigstore_trusted_root.sha256 | test("^[0-9a-f]{64}$"))
        and .signing.oidc_issuer == "https://token.actions.githubusercontent.com"
    ' "$POLICY_FILE" >/dev/null || fail "release policy is invalid"
}

validate_semver_tag() {
    local tag="$1"
    [[ "$tag" =~ ^v(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)(-([0-9A-Za-z-]+\.)*[0-9A-Za-z-]+)?(\+([0-9A-Za-z-]+\.)*[0-9A-Za-z-]+)?$ ]] \
        || fail "tag is not strict v-prefixed semantic version: $tag"
}

validate_revision() {
    [[ "$1" =~ ^[0-9a-f]{40}$ ]] || fail "revision must be a full lowercase Git SHA"
}

validate_toolchain_file() {
    local source_root="$1"
    local expected actual
    expected="$(policy '.toolchain')"
    [ -f "$source_root/rust-toolchain.toml" ] || fail "rust-toolchain.toml is missing"
    actual="$(awk -F '"' '/^[[:space:]]*channel[[:space:]]*=/ { print $2; exit }' \
        "$source_root/rust-toolchain.toml")"
    [ "$actual" = "$expected" ] \
        || fail "toolchain must be pinned to $expected, found ${actual:-missing}"
    case "$actual" in
        stable | beta | nightly | *-stable | *-beta | *-nightly)
            fail "moving Rust toolchains are not release inputs"
            ;;
    esac
}

preflight() {
    local tag="$1"
    local revision="$2"
    local source_root="${3:-$ROOT_DIR}"
    local version head tag_revision metadata versions

    validate_policy
    validate_semver_tag "$tag"
    validate_revision "$revision"
    need cargo
    need git

    [ -d "$source_root/.git" ] || fail "source root is not a Git checkout: $source_root"
    [ -z "$(git -C "$source_root" status --porcelain --untracked-files=all)" ] \
        || fail "source checkout is dirty"
    head="$(git -C "$source_root" rev-parse HEAD)"
    [ "$head" = "$revision" ] || fail "revision does not match checkout HEAD"
    git -C "$source_root" show-ref --verify --quiet "refs/tags/$tag" \
        || fail "release tag does not exist in the checkout"
    tag_revision="$(git -C "$source_root" rev-list -n 1 "$tag")"
    [ "$tag_revision" = "$revision" ] || fail "release tag does not resolve to the requested SHA"

    [ -f "$source_root/Cargo.lock" ] || fail "Cargo.lock is missing"
    git -C "$source_root" ls-files --error-unmatch Cargo.lock >/dev/null 2>&1 \
        || fail "Cargo.lock is not tracked"
    validate_toolchain_file "$source_root"

    metadata="$(
        cd "$source_root"
        cargo metadata --manifest-path Cargo.toml --locked --no-deps --format-version 1
    )" || fail "locked Cargo metadata failed"
    version="${tag#v}"
    versions="$(jq -r '.packages[].version' <<< "$metadata" | LC_ALL=C sort -u)"
    [ "$versions" = "$version" ] \
        || fail "release tag version does not match every workspace package: $versions"
    jq -e --arg package "$(policy '.package')" --arg version "$version" '
        any(.packages[]; .name == $package and .version == $version)
    ' <<< "$metadata" >/dev/null || fail "root release package/version is missing"
}

target_policy() {
    local target="$1"
    jq -ec --arg target "$target" '.targets[] | select(.target == $target)' "$POLICY_FILE"
}

run_startup_budget() {
    local binary="$1"
    local version="$2"
    local seconds="$3"
    local python_command="${PYTHON_COMMAND:-python3}"
    need "$python_command"
    "$python_command" - "$binary" "$version" "$seconds" <<'PY'
import subprocess
import sys

binary, version, seconds = sys.argv[1], sys.argv[2], float(sys.argv[3])
try:
    completed = subprocess.run(
        [binary, "--version"],
        check=False,
        capture_output=True,
        text=True,
        timeout=seconds,
    )
except subprocess.TimeoutExpired as error:
    raise SystemExit(f"--version exceeded {seconds:g} seconds") from error

expected = f"scorchkit {version}"
if completed.returncode != 0:
    raise SystemExit(f"--version exited {completed.returncode}")
if completed.stdout.strip() != expected:
    raise SystemExit(f"unexpected --version output: {completed.stdout!r}")
if completed.stderr:
    raise SystemExit(f"unexpected --version stderr: {completed.stderr!r}")
PY
}

validate_binary_target() {
    local binary="$1"
    local target="$2"
    local python_command="${PYTHON_COMMAND:-python3}"
    need "$python_command"
    "$python_command" - "$binary" "$target" <<'PY'
import pathlib
import struct
import sys

path = pathlib.Path(sys.argv[1])
target = sys.argv[2]
with path.open("rb") as stream:
    data = stream.read(512)

def reject(reason):
    raise SystemExit(f"{path.name} is not a {target} executable: {reason}")

if target == "x86_64-unknown-linux-gnu":
    if len(data) < 20 or data[:4] != b"\x7fELF":
        reject("missing ELF header")
    if data[4] != 2 or data[5] != 1:
        reject("expected little-endian ELF64")
    file_type, machine = struct.unpack_from("<HH", data, 16)
    if file_type not in (2, 3) or machine != 62:
        reject("expected x86-64 executable or PIE")
elif target == "x86_64-pc-windows-msvc":
    if len(data) < 64 or data[:2] != b"MZ":
        reject("missing DOS/PE header")
    pe_offset = struct.unpack_from("<I", data, 0x3C)[0]
    if pe_offset + 24 > len(data) or data[pe_offset:pe_offset + 4] != b"PE\0\0":
        reject("missing PE signature")
    machine, _, _, _, _, _, characteristics = struct.unpack_from("<HHIIIHH", data, pe_offset + 4)
    if machine != 0x8664 or characteristics & 0x0002 == 0:
        reject("expected x86-64 PE executable")
elif target in ("aarch64-apple-darwin", "x86_64-apple-darwin"):
    if len(data) < 16 or data[:4] != b"\xcf\xfa\xed\xfe":
        reject("missing little-endian Mach-O 64 header")
    cpu_type = struct.unpack_from("<I", data, 4)[0]
    file_type = struct.unpack_from("<I", data, 12)[0]
    expected_cpu = 0x0100000C if target.startswith("aarch64") else 0x01000007
    if cpu_type != expected_cpu or file_type != 2:
        reject("unexpected Mach-O CPU or file type")
else:
    reject("unsupported policy target")
PY
}

build_target() {
    local target="$1"
    local source_a="$2"
    local source_b="$3"
    local output_dir="$4"
    local target_json asset extension version tag revision epoch feature_csv budget build_root
    local source_a_real source_b_real target_a target_b binary_a binary_b output
    local rustflags_a rustflags_b

    validate_policy
    target_json="$(target_policy "$target")" || fail "unsupported release target: $target"
    source_a_real="$(cd "$source_a" && pwd -P)"
    source_b_real="$(cd "$source_b" && pwd -P)"
    [ "$source_a_real" != "$source_b_real" ] || fail "double builds require distinct source paths"

    tag="${SCORCHKIT_RELEASE_TAG:-}"
    revision="${SCORCHKIT_RELEASE_REVISION:-}"
    [ -n "$tag" ] && [ -n "$revision" ] \
        || fail "SCORCHKIT_RELEASE_TAG and SCORCHKIT_RELEASE_REVISION are required"
    preflight "$tag" "$revision" "$source_a_real"
    preflight "$tag" "$revision" "$source_b_real"

    asset="$(jq -r '.asset' <<< "$target_json")"
    extension=""
    [[ "$asset" == *.exe ]] && extension=".exe"
    version="${tag#v}"
    epoch="$(git -C "$source_a_real" show -s --format=%ct "$revision")"
    [[ "$epoch" =~ ^[1-9][0-9]*$ ]] || fail "source date epoch is invalid"
    feature_csv="$(policy '.features | join(",")')"
    budget="$(policy '.budgets.binary_bytes')"
    build_root="$(make_release_temp)"
    target_a="$build_root/target-a"
    target_b="$build_root/target-b"
    mkdir -p "$target_a" "$target_b" "$output_dir"

    rustflags_a="--remap-path-prefix=$source_a_real=/scorchkit --remap-path-prefix=$target_a=/scorchkit-target -C strip=symbols"
    rustflags_b="--remap-path-prefix=$source_b_real=/scorchkit --remap-path-prefix=$target_b=/scorchkit-target -C strip=symbols"

    (
        cd "$source_a_real"
        CARGO_INCREMENTAL=0 CARGO_TARGET_DIR="$target_a" SOURCE_DATE_EPOCH="$epoch" \
            RUSTFLAGS="$rustflags_a" TZ=UTC LC_ALL=C \
            cargo build --release --locked --target "$target" --no-default-features \
                --features "$feature_csv" --bin scorchkit
    )
    (
        cd "$source_b_real"
        CARGO_INCREMENTAL=0 CARGO_TARGET_DIR="$target_b" SOURCE_DATE_EPOCH="$epoch" \
            RUSTFLAGS="$rustflags_b" TZ=UTC LC_ALL=C \
            cargo build --release --locked --target "$target" --no-default-features \
                --features "$feature_csv" --bin scorchkit
    )

    binary_a="$target_a/$target/release/scorchkit$extension"
    binary_b="$target_b/$target/release/scorchkit$extension"
    [ -f "$binary_a" ] && [ -f "$binary_b" ] || fail "expected release binary was not built"
    validate_binary_target "$binary_a" "$target"
    validate_binary_target "$binary_b" "$target"
    cmp --silent "$binary_a" "$binary_b" \
        || fail "double builds are not byte-identical for $target"
    [ "$(file_size "$binary_a")" -le "$budget" ] \
        || fail "binary exceeds the $budget-byte release ceiling: $asset"
    run_startup_budget "$binary_a" "$version" "$(policy '.budgets.startup_seconds')"

    output="$output_dir/$asset"
    cp -- "$binary_a" "$output"
    chmod 0755 "$output"
    printf '%s  %s\n' "$(sha256_file "$output")" "$asset"
    remove_release_temp "$build_root"
}

install_tools() {
    local output_dir="$1"
    local work syft_archive cosign_binary trusted_root expected actual entries
    need curl
    need tar
    validate_policy
    mkdir -p "$output_dir"
    work="$(make_release_temp)"
    syft_archive="$work/syft.tar.gz"
    cosign_binary="$work/cosign"
    trusted_root="$work/sigstore-trusted-root.json"

    curl --proto '=https' --tlsv1.2 --fail --location --silent --show-error \
        "$(policy '.tools.syft.url')" --output "$syft_archive"
    expected="$(policy '.tools.syft.sha256')"
    actual="$(sha256_file "$syft_archive")"
    [ "$actual" = "$expected" ] || fail "Syft release checksum mismatch"
    entries="$(tar -tzf "$syft_archive")"
    [ -n "$entries" ] || fail "Syft archive is empty"
    if grep -Eq '(^/|(^|/)\.\.(/|$))' <<< "$entries"; then
        fail "Syft archive contains an unsafe path"
    fi
    tar -xzf "$syft_archive" -C "$work"
    [ -f "$work/syft" ] || fail "Syft archive does not contain the expected binary"
    cp -- "$work/syft" "$output_dir/syft"
    chmod 0755 "$output_dir/syft"

    curl --proto '=https' --tlsv1.2 --fail --location --silent --show-error \
        "$(policy '.tools.cosign.url')" --output "$cosign_binary"
    expected="$(policy '.tools.cosign.sha256')"
    actual="$(sha256_file "$cosign_binary")"
    [ "$actual" = "$expected" ] || fail "Cosign release checksum mismatch"
    cp -- "$cosign_binary" "$output_dir/cosign"
    chmod 0755 "$output_dir/cosign"

    curl --proto '=https' --tlsv1.2 --fail --location --silent --show-error \
        "$(policy '.tools.sigstore_trusted_root.url')" --output "$trusted_root"
    expected="$(policy '.tools.sigstore_trusted_root.sha256')"
    actual="$(sha256_file "$trusted_root")"
    [ "$actual" = "$expected" ] || fail "Sigstore trusted-root checksum mismatch"
    jq -e '
        .mediaType == "application/vnd.dev.sigstore.trustedroot+json;version=0.1"
        and (.tlogs | length > 0)
        and (.certificateAuthorities | length > 0)
    ' "$trusted_root" >/dev/null || fail "Sigstore trusted-root document is invalid"
    cp -- "$trusted_root" "$output_dir/sigstore-trusted-root.json"

    [ "$("$output_dir/syft" version -o json | jq -r '.version')" \
        = "$(policy '.tools.syft.version')" ] || fail "installed Syft version mismatch"
    remove_release_temp "$work"
}

identity_for() {
    local repository="$1"
    local tag="$2"
    local template
    template="$(policy '.signing.identity_template')"
    template="${template//\{repository\}/$repository}"
    template="${template//\{tag\}/$tag}"
    printf '%s\n' "$template"
}

iso8601_from_epoch() {
    local epoch="$1"
    if date -u -d "@$epoch" '+%Y-%m-%dT%H:%M:%SZ' >/dev/null 2>&1; then
        date -u -d "@$epoch" '+%Y-%m-%dT%H:%M:%SZ'
    else
        date -u -r "$epoch" '+%Y-%m-%dT%H:%M:%SZ'
    fi
}

expected_binary_names() {
    jq -r '.targets[].asset' "$POLICY_FILE" | LC_ALL=C sort
}

expected_sbom_names() {
    while IFS= read -r name; do
        printf '%s.cdx.json\n' "$name"
    done < <(expected_binary_names)
}

checksum_subject_names() {
    expected_binary_names
    expected_sbom_names
    printf '%s\n' "$MANIFEST_NAME" "$PROVENANCE_NAME"
}

signature_subject_names() {
    checksum_subject_names
    printf '%s\n' "$CHECKSUM_NAME"
}

write_checksums() {
    local stage="$1"
    local asset
    : > "$stage/$CHECKSUM_NAME"
    while IFS= read -r asset; do
        printf '%s  %s\n' "$(sha256_file "$stage/$asset")" "$asset" \
            >> "$stage/$CHECKSUM_NAME"
    done < <(checksum_subject_names | LC_ALL=C sort)
}

write_provenance() {
    local stage="$1"
    local tag="$2"
    local revision="$3"
    local repository="$4"
    local source_epoch="$5"
    local work="$6"
    local subject name digest identity feature_json target_json invocation build_type
    local subjects_file="$work/provenance-subjects.jsonl"
    : > "$subjects_file"
    while IFS= read -r name; do
        digest="$(sha256_file "$stage/$name")"
        jq -cn --arg name "$name" --arg digest "$digest" \
            '{name: $name, digest: {sha256: $digest}}' >> "$subjects_file"
    done < <(
        expected_binary_names
        expected_sbom_names
        printf '%s\n' "$MANIFEST_NAME"
    )
    subject="$(jq -s 'sort_by(.name)' "$subjects_file")"
    identity="$(identity_for "$repository" "$tag")"
    feature_json="$(policy '.features')"
    target_json="$(policy '.targets | map(.target) | sort')"
    invocation="https://github.com/$repository/actions/runs/${GITHUB_RUN_ID:-local}/attempts/${GITHUB_RUN_ATTEMPT:-1}"
    build_type="https://github.com/$repository/blob/$revision/docs/guide/releases.md#release-qualification-v1"
    jq -nS -c \
        --argjson subject "$subject" \
        --arg tag "$tag" \
        --arg revision "$revision" \
        --arg repository "$repository" \
        --arg identity "$identity" \
        --arg invocation "$invocation" \
        --arg build_type "$build_type" \
        --arg toolchain "$(policy '.toolchain')" \
        --argjson features "$feature_json" \
        --argjson targets "$target_json" \
        --argjson source_epoch "$source_epoch" '
        {
          "_type": "https://in-toto.io/Statement/v1",
          "subject": $subject,
          "predicateType": "https://slsa.dev/provenance/v1",
          "predicate": {
            "buildDefinition": {
              "buildType": $build_type,
              "externalParameters": {
                "tag": $tag,
                "revision": $revision,
                "toolchain": $toolchain,
                "features": $features,
                "targets": $targets,
                "source_date_epoch": $source_epoch
              },
              "internalParameters": {},
              "resolvedDependencies": [
                {
                  "uri": ("git+https://github.com/" + $repository + "@" + $revision),
                  "digest": {"gitCommit": $revision}
                }
              ]
            },
            "runDetails": {
              "builder": {"id": $identity},
              "metadata": {"invocationId": $invocation}
            }
          }
        }
    ' > "$stage/$PROVENANCE_NAME"
}

assemble_stage() {
    local stage="$1"
    local tag="$2"
    local revision="$3"
    local repository="${4:-$(policy '.repository')}"
    local source_epoch="${5:-}"
    local version syft_version work artifacts_file target_json target asset binary_digest size
    local sbom_name sbom_temp sbom_digest timestamp serial_hex serial identity feature_json

    validate_policy
    validate_semver_tag "$tag"
    validate_revision "$revision"
    [[ "$repository" =~ ^[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+$ ]] \
        || fail "repository identity is invalid"
    [ "$repository" = "$(policy '.repository')" ] \
        || fail "repository does not match release policy"
    [ -d "$stage" ] || fail "stage directory is missing"
    need syft
    syft_version="$(syft version -o json | jq -r '.version // empty')"
    [ "$syft_version" = "$(policy '.tools.syft.version')" ] \
        || fail "Syft version must be exactly $(policy '.tools.syft.version')"

    version="${tag#v}"
    if [ -z "$source_epoch" ]; then
        source_epoch="${SOURCE_DATE_EPOCH:-}"
    fi
    [[ "$source_epoch" =~ ^[1-9][0-9]*$ ]] || fail "source date epoch is required"
    timestamp="$(iso8601_from_epoch "$source_epoch")"
    work="$(make_release_temp)"
    artifacts_file="$work/artifacts.jsonl"
    : > "$artifacts_file"

    while IFS= read -r target_json; do
        target="$(jq -r '.target' <<< "$target_json")"
        asset="$(jq -r '.asset' <<< "$target_json")"
        [ -f "$stage/$asset" ] && [ ! -L "$stage/$asset" ] \
            || fail "missing or redirected binary: $asset"
        validate_binary_target "$stage/$asset" "$target"
        size="$(file_size "$stage/$asset")"
        [ "$size" -gt 0 ] && [ "$size" -le "$(policy '.budgets.binary_bytes')" ] \
            || fail "binary size is outside the release budget: $asset"
        binary_digest="$(sha256_file "$stage/$asset")"
        sbom_name="$asset.cdx.json"
        sbom_temp="$work/$sbom_name"
        syft "file:$stage/$asset" -q --source-name "$asset" --source-version "$version" \
            -o 'cyclonedx-json@1.6' > "$sbom_temp"
        serial_hex="${binary_digest:0:32}"
        serial="urn:uuid:${serial_hex:0:8}-${serial_hex:8:4}-${serial_hex:12:4}-${serial_hex:16:4}-${serial_hex:20:12}"
        identity="scorchkit:$target@$binary_digest"
        jq -S -c \
            --arg timestamp "$timestamp" \
            --arg serial "$serial" \
            --arg identity "$identity" \
            --arg asset "$asset" \
            --arg version "$version" \
            --arg digest "$binary_digest" '
            .bomFormat = "CycloneDX"
            | .specVersion = "1.6"
            | .serialNumber = $serial
            | .metadata.timestamp = $timestamp
            | .metadata.component = {
                "bom-ref": $identity,
                "type": "file",
                "name": $asset,
                "version": ("sha256:" + $digest),
                "properties": [
                  {"name": "scorchkit.release.version", "value": $version}
                ]
              }
        ' "$sbom_temp" > "$stage/$sbom_name"
        sbom_digest="$(sha256_file "$stage/$sbom_name")"
        jq -cn \
            --arg name "$asset" \
            --arg target "$target" \
            --argjson size "$size" \
            --arg digest "$binary_digest" \
            --arg sbom_name "$sbom_name" \
            --arg sbom_digest "$sbom_digest" '
            {
              name: $name,
              target: $target,
              size: $size,
              sha256: $digest,
              sbom: {
                name: $sbom_name,
                sha256: $sbom_digest,
                format: "CycloneDX",
                spec_version: "1.6"
              }
            }
        ' >> "$artifacts_file"
    done < <(jq -c '.targets[]' "$POLICY_FILE")

    feature_json="$(policy '.features')"
    jq -nS -c \
        --arg schema "scorchkit.release-manifest/v1" \
        --arg name "$(policy '.package')" \
        --arg version "$version" \
        --arg tag "$tag" \
        --arg repository "$repository" \
        --arg revision "$revision" \
        --arg toolchain "$(policy '.toolchain')" \
        --argjson features "$feature_json" \
        --argjson source_epoch "$source_epoch" \
        --argjson artifacts "$(jq -s 'sort_by(.target)' "$artifacts_file")" '
        {
          schema: $schema,
          name: $name,
          version: $version,
          tag: $tag,
          source: {repository: $repository, revision: $revision},
          build: {
            toolchain: $toolchain,
            features: $features,
            source_date_epoch: $source_epoch
          },
          artifacts: $artifacts
        }
    ' > "$stage/$MANIFEST_NAME"

    write_provenance "$stage" "$tag" "$revision" "$repository" "$source_epoch" "$work"
    write_checksums "$stage"
    remove_release_temp "$work"
    verify_stage "$stage"
}

verify_file_inventory() {
    local stage="$1"
    local work actual expected bundle_count subject_count name
    work="$(make_release_temp)"
    actual="$work/actual"
    expected="$work/expected"
    if find "$stage" -mindepth 1 -type l -print -quit | grep -q .; then
        remove_release_temp "$work"
        fail "release stage contains a symlink"
    fi
    if find "$stage" -mindepth 1 ! -type f -print -quit | grep -q .; then
        remove_release_temp "$work"
        fail "release stage contains a non-file entry"
    fi
    find "$stage" -mindepth 1 -maxdepth 1 -type f -printf '%f\n' | LC_ALL=C sort > "$actual"
    {
        signature_subject_names
    } | LC_ALL=C sort > "$expected"
    bundle_count="$(find "$stage" -mindepth 1 -maxdepth 1 -type f \
        -name '*.sigstore.json' | wc -l | tr -d '[:space:]')"
    subject_count="$(signature_subject_names | wc -l | tr -d '[:space:]')"
    if [ "$bundle_count" -ne 0 ] && [ "$bundle_count" -ne "$subject_count" ]; then
        remove_release_temp "$work"
        fail "release stage contains a partial signature bundle set"
    fi
    if [ "$bundle_count" -eq "$subject_count" ]; then
        while IFS= read -r name; do
            printf '%s.sigstore.json\n' "$name"
        done < <(signature_subject_names)
    fi | LC_ALL=C sort -o "$work/bundles"
    cat "$work/bundles" >> "$expected"
    LC_ALL=C sort -o "$expected" "$expected"
    if ! cmp --silent "$actual" "$expected"; then
        echo "actual release files:" >&2
        cat "$actual" >&2
        echo "expected release files:" >&2
        cat "$expected" >&2
        remove_release_temp "$work"
        fail "release file inventory is not exact"
    fi
    remove_release_temp "$work"
}

verify_manifest() {
    local stage="$1"
    local manifest="$stage/$MANIFEST_NAME"
    local expected_targets expected_features artifact target asset entry size digest sbom_name
    local sbom_digest version tag budget
    [ -f "$manifest" ] && [ ! -L "$manifest" ] || fail "release manifest is missing"
    expected_targets="$(policy '.targets | map(.target) | sort')"
    expected_features="$(policy '.features')"
    jq -e \
        --argjson targets "$expected_targets" \
        --argjson features "$expected_features" \
        --arg toolchain "$(policy '.toolchain')" \
        --arg repository "$(policy '.repository')" '
        keys == ["artifacts", "build", "name", "schema", "source", "tag", "version"]
        and .schema == "scorchkit.release-manifest/v1"
        and .name == "scorchkit"
        and (.version | test("^(0|[1-9][0-9]*)\\.(0|[1-9][0-9]*)\\.(0|[1-9][0-9]*)(-[0-9A-Za-z.-]+)?(\\+[0-9A-Za-z.-]+)?$"))
        and .tag == ("v" + .version)
        and (.source | keys == ["repository", "revision"])
        and .source.repository == $repository
        and (.source.revision | test("^[0-9a-f]{40}$"))
        and (.build | keys == ["features", "source_date_epoch", "toolchain"])
        and .build.toolchain == $toolchain
        and .build.features == $features
        and (.build.source_date_epoch | type == "number" and . > 0 and floor == .)
        and (.artifacts | length == 4)
        and (.artifacts | map(.target) | sort == $targets)
        and ((.artifacts | map(.target) | unique | length) == 4)
        and ((.artifacts | map(.name) | unique | length) == 4)
        and (.artifacts | all(
          keys == ["name", "sbom", "sha256", "size", "target"]
          and (.sha256 | test("^[0-9a-f]{64}$"))
          and (.size | type == "number" and . > 0 and floor == .)
          and (.sbom | keys == ["format", "name", "sha256", "spec_version"])
          and .sbom.format == "CycloneDX"
          and .sbom.spec_version == "1.6"
          and (.sbom.sha256 | test("^[0-9a-f]{64}$"))
        ))
    ' "$manifest" >/dev/null || fail "release manifest structure is invalid"

    version="$(jq -r '.version' "$manifest")"
    tag="$(jq -r '.tag' "$manifest")"
    validate_semver_tag "$tag"
    budget="$(policy '.budgets.binary_bytes')"
    while IFS= read -r artifact; do
        target="$(jq -r '.target' <<< "$artifact")"
        asset="$(jq -r '.asset' <<< "$artifact")"
        entry="$(jq -ec --arg target "$target" '.artifacts[] | select(.target == $target)' \
            "$manifest")"
        [ "$(jq -r '.name' <<< "$entry")" = "$asset" ] \
            || fail "manifest asset does not match target policy: $target"
        validate_binary_target "$stage/$asset" "$target"
        size="$(file_size "$stage/$asset")"
        [ "$size" -le "$budget" ] || fail "binary exceeds the release budget: $asset"
        digest="$(sha256_file "$stage/$asset")"
        [ "$(jq -r '.size' <<< "$entry")" = "$size" ] \
            || fail "manifest size mismatch: $asset"
        [ "$(jq -r '.sha256' <<< "$entry")" = "$digest" ] \
            || fail "manifest digest mismatch: $asset"
        sbom_name="$(jq -r '.sbom.name' <<< "$entry")"
        [ "$sbom_name" = "$asset.cdx.json" ] || fail "manifest SBOM name mismatch: $asset"
        sbom_digest="$(sha256_file "$stage/$sbom_name")"
        [ "$(jq -r '.sbom.sha256' <<< "$entry")" = "$sbom_digest" ] \
            || fail "manifest SBOM digest mismatch: $asset"
        jq -e \
            --arg asset "$asset" \
            --arg version "$version" \
            --arg identity "scorchkit:$target@$digest" \
            --arg digest "$digest" \
            --arg syft_version "$(policy '.tools.syft.version')" '
            .bomFormat == "CycloneDX"
            and .specVersion == "1.6"
            and .metadata.component.name == $asset
            and .metadata.component["bom-ref"] == $identity
            and .metadata.component.version == ("sha256:" + $digest)
            and any(.metadata.tools.components[]?;
              .name == "syft" and .version == $syft_version)
            and any(.metadata.component.properties[];
              .name == "scorchkit.release.version" and .value == $version)
        ' "$stage/$sbom_name" >/dev/null || fail "SBOM identity mismatch: $sbom_name"
    done < <(jq -c '.targets[]' "$POLICY_FILE")
}

verify_provenance() {
    local stage="$1"
    local provenance="$stage/$PROVENANCE_NAME"
    local manifest="$stage/$MANIFEST_NAME"
    local repository tag revision identity expected_subjects work name source_epoch
    local expected_features expected_targets dependency build_type invocation_prefix
    [ -f "$provenance" ] && [ ! -L "$provenance" ] || fail "provenance is missing"
    repository="$(jq -r '.source.repository' "$manifest")"
    tag="$(jq -r '.tag' "$manifest")"
    revision="$(jq -r '.source.revision' "$manifest")"
    source_epoch="$(jq -r '.build.source_date_epoch' "$manifest")"
    identity="$(identity_for "$repository" "$tag")"
    expected_features="$(policy '.features')"
    expected_targets="$(policy '.targets | map(.target) | sort')"
    dependency="git+https://github.com/$repository@$revision"
    build_type="https://github.com/$repository/blob/$revision/docs/guide/releases.md#release-qualification-v1"
    invocation_prefix="https://github.com/$repository/actions/runs/"
    work="$(make_release_temp)"
    : > "$work/subjects.jsonl"
    while IFS= read -r name; do
        jq -cn --arg name "$name" --arg digest "$(sha256_file "$stage/$name")" \
            '{name: $name, digest: {sha256: $digest}}' >> "$work/subjects.jsonl"
    done < <(
        expected_binary_names
        expected_sbom_names
        printf '%s\n' "$MANIFEST_NAME"
    )
    expected_subjects="$(jq -s 'sort_by(.name)' "$work/subjects.jsonl")"
    jq -e \
        --argjson subjects "$expected_subjects" \
        --arg revision "$revision" \
        --arg identity "$identity" \
        --arg toolchain "$(policy '.toolchain')" \
        --arg tag "$tag" \
        --argjson source_epoch "$source_epoch" \
        --argjson features "$expected_features" \
        --argjson targets "$expected_targets" \
        --arg dependency "$dependency" \
        --arg build_type "$build_type" \
        --arg invocation_prefix "$invocation_prefix" '
        ._type == "https://in-toto.io/Statement/v1"
        and .predicateType == "https://slsa.dev/provenance/v1"
        and (.subject | sort_by(.name)) == $subjects
        and .predicate.buildDefinition.buildType == $build_type
        and .predicate.buildDefinition.externalParameters == {
          features: $features,
          revision: $revision,
          source_date_epoch: $source_epoch,
          tag: $tag,
          targets: $targets,
          toolchain: $toolchain
        }
        and .predicate.buildDefinition.internalParameters == {}
        and .predicate.buildDefinition.resolvedDependencies == [{
          uri: $dependency,
          digest: {gitCommit: $revision}
        }]
        and .predicate.runDetails.builder == {id: $identity}
        and (.predicate.runDetails.metadata | keys == ["invocationId"])
        and (.predicate.runDetails.metadata.invocationId | startswith($invocation_prefix))
    ' "$provenance" >/dev/null || {
        remove_release_temp "$work"
        fail "provenance identity is invalid"
    }
    remove_release_temp "$work"
}

verify_checksums() {
    local stage="$1"
    local checksum="$stage/$CHECKSUM_NAME"
    local work names expected_names name expected actual
    [ -f "$checksum" ] && [ ! -L "$checksum" ] || fail "checksum document is missing"
    work="$(make_release_temp)"
    names="$work/names"
    expected_names="$work/expected"
    awk 'NF == 2 && $1 ~ /^[0-9a-f]{64}$/ { print $2; next } { exit 1 }' "$checksum" \
        | LC_ALL=C sort > "$names" || {
            remove_release_temp "$work"
            fail "checksum document is malformed"
        }
    checksum_subject_names | LC_ALL=C sort > "$expected_names"
    cmp --silent "$names" "$expected_names" || {
        remove_release_temp "$work"
        fail "checksum subject inventory is not exact"
    }
    while read -r expected name; do
        actual="$(sha256_file "$stage/$name")"
        [ "$actual" = "$expected" ] || {
            remove_release_temp "$work"
            fail "checksum mismatch: $name"
        }
    done < "$checksum"
    remove_release_temp "$work"
}

verify_stage() {
    local stage="$1"
    validate_policy
    [ -d "$stage" ] || fail "release stage is missing"
    verify_file_inventory "$stage"
    verify_manifest "$stage"
    verify_provenance "$stage"
    verify_checksums "$stage"
}

subjects() {
    local stage="$1"
    verify_stage "$stage"
    signature_subject_names | LC_ALL=C sort
}

cosign_version() {
    local output version
    output="$(cosign version --json)" || fail "Cosign version probe failed"
    version="$(jq -r '.gitVersion // .GitVersion // empty' <<< "$output")"
    printf '%s\n' "${version#v}"
}

sign_subjects() {
    local stage="$1"
    local identity="$2"
    local revision="$3"
    local name
    validate_revision "$revision"
    need cosign
    [ "$(cosign_version)" = "$(policy '.tools.cosign.version')" ] \
        || fail "Cosign version must be exactly $(policy '.tools.cosign.version')"
    [ "${GITHUB_ACTIONS:-}" = "true" ] || fail "keyless signing requires GitHub Actions OIDC"
    [ "${GITHUB_SHA:-}" = "$revision" ] || fail "signing revision does not match GITHUB_SHA"
    [ "https://github.com/${GITHUB_WORKFLOW_REF:-}" = "$identity" ] \
        || fail "signing identity does not match GITHUB_WORKFLOW_REF"
    verify_stage "$stage"
    while IFS= read -r name; do
        cosign sign-blob "$stage/$name" --yes --bundle "$stage/$name.sigstore.json"
    done < <(signature_subject_names | LC_ALL=C sort)
}

verify_one_signature() {
    local subject="$1"
    local bundle="$2"
    local identity="$3"
    local revision="$4"
    local trusted_root
    trusted_root="${SCORCHKIT_SIGSTORE_TRUSTED_ROOT:-$(dirname "$(command -v cosign)")/sigstore-trusted-root.json}"
    [ -f "$trusted_root" ] && [ ! -L "$trusted_root" ] \
        || fail "pinned Sigstore trusted root is unavailable"
    [ "$(sha256_file "$trusted_root")" = "$(policy '.tools.sigstore_trusted_root.sha256')" ] \
        || fail "pinned Sigstore trusted root digest does not match policy"
    cosign verify-blob "$subject" --bundle "$bundle" --trusted-root "$trusted_root" \
        --certificate-identity "$identity" \
        --certificate-oidc-issuer "$(policy '.signing.oidc_issuer')" \
        --certificate-github-workflow-sha "$revision" >/dev/null
}

verify_signatures() {
    local stage="$1"
    local identity="$2"
    local revision="$3"
    local name
    validate_revision "$revision"
    need cosign
    [ "$(cosign_version)" = "$(policy '.tools.cosign.version')" ] \
        || fail "Cosign version must be exactly $(policy '.tools.cosign.version')"
    verify_stage "$stage"
    while IFS= read -r name; do
        [ -f "$stage/$name.sigstore.json" ] && [ ! -L "$stage/$name.sigstore.json" ] \
            || fail "signature bundle is missing: $name"
        verify_one_signature "$stage/$name" "$stage/$name.sigstore.json" "$identity" "$revision" \
            || fail "signature verification failed: $name"
    done < <(signature_subject_names | LC_ALL=C sort)
}

verify_signature_negatives() {
    local stage="$1"
    local identity="$2"
    local revision="$3"
    local first bundle work tampered wrong_revision
    verify_signatures "$stage" "$identity" "$revision"
    first="$(signature_subject_names | LC_ALL=C sort | head -n 1)"
    bundle="$stage/$first.sigstore.json"
    wrong_revision="0000000000000000000000000000000000000000"
    if verify_one_signature "$stage/$first" "$bundle" "${identity}-wrong" "$revision"; then
        fail "wrong signing identity was accepted"
    fi
    if verify_one_signature "$stage/$first" "$bundle" "$identity" "$wrong_revision"; then
        fail "wrong signing revision was accepted"
    fi
    work="$(make_release_temp)"
    tampered="$work/$first"
    cp -- "$stage/$first" "$tampered"
    printf 'tampered\n' >> "$tampered"
    if verify_one_signature "$tampered" "$bundle" "$identity" "$revision"; then
        remove_release_temp "$work"
        fail "tampered signed subject was accepted"
    fi
    remove_release_temp "$work"
}

expect_failure() {
    local label="$1"
    local status
    shift
    set +e
    (set -e; "$@") >/dev/null 2>&1
    status=$?
    set -e
    if [ "$status" -eq 0 ]; then
        fail "selftest accepted $label"
    fi
}

selftest() {
    local work fake_bin stage repository tag revision epoch asset original repo repo_revision
    local linux_asset mac_asset
    validate_policy
    work="$(make_release_temp)"
    fake_bin="$work/bin"
    stage="$work/stage"
    mkdir -p "$fake_bin" "$stage"
    cat > "$fake_bin/syft" <<'SYFT'
#!/usr/bin/env bash
set -euo pipefail
if [ "${1:-}" = "version" ]; then
    printf '{"version":"1.50.0"}\n'
    exit 0
fi
asset=""
version=""
while [ "$#" -gt 0 ]; do
    case "$1" in
        --source-name) asset="$2"; shift 2 ;;
        --source-version) version="$2"; shift 2 ;;
        *) shift ;;
    esac
done
printf '{"bomFormat":"CycloneDX","specVersion":"1.6","serialNumber":"urn:uuid:00000000-0000-0000-0000-000000000000","version":1,"metadata":{"timestamp":"1970-01-01T00:00:00Z","tools":{"components":[{"type":"application","name":"syft","version":"1.50.0"}]},"component":{"bom-ref":"placeholder","type":"file","name":"%s","version":"%s"}},"components":[]}\n' "$asset" "$version"
SYFT
    chmod 0755 "$fake_bin/syft"

    need python3
    python3 - "$stage" "$POLICY_FILE" <<'PY'
import json
import pathlib
import struct
import sys

stage = pathlib.Path(sys.argv[1])
policy = json.loads(pathlib.Path(sys.argv[2]).read_text())
for entry in policy["targets"]:
    target = entry["target"]
    data = bytearray(512)
    if target == "x86_64-unknown-linux-gnu":
        data[:6] = b"\x7fELF\x02\x01"
        struct.pack_into("<HH", data, 16, 3, 62)
    elif target == "x86_64-pc-windows-msvc":
        data[:2] = b"MZ"
        struct.pack_into("<I", data, 0x3C, 128)
        data[128:132] = b"PE\0\0"
        struct.pack_into("<HHIIIHH", data, 132, 0x8664, 0, 0, 0, 0, 0, 0x0002)
    else:
        data[:4] = b"\xcf\xfa\xed\xfe"
        cpu_type = 0x0100000C if target.startswith("aarch64") else 0x01000007
        struct.pack_into("<I", data, 4, cpu_type)
        struct.pack_into("<I", data, 12, 2)
    (stage / entry["asset"]).write_bytes(data)
PY
    repository="$(policy '.repository')"
    tag="v3.0.0"
    revision="aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
    epoch=1700000000
    PATH="$fake_bin:$PATH" assemble_stage "$stage" "$tag" "$revision" "$repository" "$epoch"
    verify_stage "$stage"

    asset="$(expected_binary_names | head -n 1)"
    original="$work/original"
    cp -- "$stage/$asset" "$original"
    printf 'tamper\n' >> "$stage/$asset"
    expect_failure "tampered binary" verify_stage "$stage"
    cp -- "$original" "$stage/$asset"
    verify_stage "$stage"

    linux_asset="$(jq -r '.targets[] | select(.target == "x86_64-unknown-linux-gnu") | .asset' \
        "$POLICY_FILE")"
    mac_asset="$(jq -r '.targets[] | select(.target == "aarch64-apple-darwin") | .asset' \
        "$POLICY_FILE")"
    cp -- "$stage/$mac_asset" "$work/mac-original"
    cp -- "$stage/$linux_asset" "$stage/$mac_asset"
    expect_failure "cross-target binary substitution" verify_stage "$stage"
    cp -- "$work/mac-original" "$stage/$mac_asset"
    verify_stage "$stage"

    printf 'unexpected\n' > "$stage/unexpected-file"
    expect_failure "unexpected release file" verify_stage "$stage"
    rm -f -- "$stage/unexpected-file"
    ln -s "$stage/$asset" "$stage/redirected"
    expect_failure "release symlink" verify_stage "$stage"
    rm -f -- "$stage/redirected"

    cp -- "$stage/$MANIFEST_NAME" "$work/manifest"
    jq '.artifacts += [.artifacts[0]]' "$work/manifest" > "$stage/$MANIFEST_NAME"
    expect_failure "duplicate manifest target" verify_stage "$stage"
    cp -- "$work/manifest" "$stage/$MANIFEST_NAME"
    verify_stage "$stage"

    cp -- "$stage/$PROVENANCE_NAME" "$work/provenance"
    cp -- "$stage/$CHECKSUM_NAME" "$work/checksums"
    jq '.predicate.buildDefinition.externalParameters.features = ["infra"]' \
        "$work/provenance" > "$stage/$PROVENANCE_NAME"
    write_checksums "$stage"
    expect_failure "provenance parameter drift" verify_stage "$stage"
    cp -- "$work/provenance" "$stage/$PROVENANCE_NAME"
    cp -- "$work/checksums" "$stage/$CHECKSUM_NAME"
    verify_stage "$stage"

    repo="$work/repo"
    mkdir -p "$repo"
    git -C "$repo" init -q
    git -C "$repo" config user.email release-selftest@example.invalid
    git -C "$repo" config user.name release-selftest
    cat > "$repo/Cargo.toml" <<'TOML'
[package]
name = "scorchkit"
version = "3.0.0"
edition = "2021"
TOML
    cat > "$repo/Cargo.lock" <<'LOCK'
# This file is automatically @generated by Cargo.
# It is not intended for manual editing.
version = 4

[[package]]
name = "scorchkit"
version = "3.0.0"
LOCK
    cp -- "$ROOT_DIR/rust-toolchain.toml" "$repo/rust-toolchain.toml"
    mkdir -p "$repo/src"
    printf 'fn main() {}\n' > "$repo/src/main.rs"
    git -C "$repo" add Cargo.toml Cargo.lock rust-toolchain.toml src/main.rs
    git -C "$repo" commit -q -m fixture
    git -C "$repo" tag v3.0.0
    git -C "$repo" tag v3.0.1
    repo_revision="$(git -C "$repo" rev-parse HEAD)"
    preflight v3.0.0 "$repo_revision" "$repo"
    expect_failure "non-semver tag" preflight release "$repo_revision" "$repo"
    expect_failure "version mismatch" preflight v3.0.1 "$repo_revision" "$repo"
    expect_failure "wrong revision" preflight v3.0.0 "$revision" "$repo"
    printf 'dirty\n' > "$repo/untracked"
    expect_failure "dirty checkout" preflight v3.0.0 "$repo_revision" "$repo"
    rm -f -- "$repo/untracked"
    mv "$repo/Cargo.lock" "$repo/Cargo.lock.saved"
    expect_failure "missing lockfile" preflight v3.0.0 "$repo_revision" "$repo"
    mv "$repo/Cargo.lock.saved" "$repo/Cargo.lock"
    printf '[toolchain]\nchannel = "stable"\n' > "$work/moving-toolchain.toml"
    mkdir -p "$work/moving"
    cp -- "$work/moving-toolchain.toml" "$work/moving/rust-toolchain.toml"
    expect_failure "moving toolchain" validate_toolchain_file "$work/moving"

    remove_release_temp "$work"
    echo "release qualification selftest OK"
}

case "${1:-}" in
    preflight)
        [ "$#" -ge 3 ] && [ "$#" -le 4 ] || { usage >&2; exit 2; }
        preflight "$2" "$3" "${4:-$ROOT_DIR}"
        ;;
    build)
        [ "$#" -eq 5 ] || { usage >&2; exit 2; }
        build_target "$2" "$3" "$4" "$5"
        ;;
    install-tools)
        [ "$#" -eq 2 ] || { usage >&2; exit 2; }
        install_tools "$2"
        ;;
    assemble)
        [ "$#" -ge 4 ] && [ "$#" -le 6 ] || { usage >&2; exit 2; }
        assemble_stage "$2" "$3" "$4" "${5:-$(policy '.repository')}" "${6:-}"
        ;;
    verify)
        [ "$#" -eq 2 ] || { usage >&2; exit 2; }
        verify_stage "$2"
        ;;
    subjects)
        [ "$#" -eq 2 ] || { usage >&2; exit 2; }
        subjects "$2"
        ;;
    sign)
        [ "$#" -eq 4 ] || { usage >&2; exit 2; }
        sign_subjects "$2" "$3" "$4"
        ;;
    verify-signatures)
        [ "$#" -eq 4 ] || { usage >&2; exit 2; }
        verify_signatures "$2" "$3" "$4"
        ;;
    verify-signature-negatives)
        [ "$#" -eq 4 ] || { usage >&2; exit 2; }
        verify_signature_negatives "$2" "$3" "$4"
        ;;
    --selftest | selftest)
        [ "$#" -eq 1 ] || { usage >&2; exit 2; }
        selftest
        ;;
    *)
        usage >&2
        exit 2
        ;;
esac
