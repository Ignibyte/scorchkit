# ScorchKit releases

ScorchKit releases are raw, target-named binaries qualified from one immutable semantic-version tag.
The release workflow builds every target twice from different clean paths, rejects unequal bytes,
then publishes only after the complete artifact set, checksums, SBOMs, provenance, and signatures
verify together. Source builds remain supported; a release does not change target authorization or
scanner behavior.

## Supported assets

| Host | Target | Asset |
|---|---|---|
| Linux x86-64 | `x86_64-unknown-linux-gnu` | `scorchkit-x86_64-unknown-linux-gnu` |
| macOS Apple silicon | `aarch64-apple-darwin` | `scorchkit-aarch64-apple-darwin` |
| macOS Intel | `x86_64-apple-darwin` | `scorchkit-x86_64-apple-darwin` |
| Windows x86-64 | `x86_64-pc-windows-msvc` | `scorchkit-x86_64-pc-windows-msvc.exe` |

The production feature set is exactly `infra,cloud,mcp`. Native cloud SDK experiments remain
quarantined and are not release defaults. Raw files avoid archive timestamp and permission drift;
after downloading a Unix asset, restore executable mode explicitly with `chmod 0755 ASSET`.

## Release qualification v1

`release/policy.json` owns target names, Rust 1.96.0, exact tool versions, release features, workflow
identity, and budgets. `bin/release.sh` enforces that policy:

```text
preflight -> native double build -> compare bytes -> aggregate exact subjects
          -> CycloneDX SBOMs -> canonical manifest -> SLSA provenance
          -> checksums -> keyless signatures -> aggregate verification
          -> draft release -> release-asset readback -> publish
```

Preflight rejects a dirty checkout, malformed or missing tag, tag/package version mismatch,
nonmatching full revision, absent or unlocked `Cargo.lock`, workspace package-version drift, and a
moving Rust channel. Builds disable incremental compilation, fix `SOURCE_DATE_EPOCH`, remap both
source and target paths, strip symbols through Rust, and compare bytes only between two builds for
the same target on the same native runner.

The workflow can be dispatched as a dry run only from the selected tag ref. Leave `publish=false`
to retain a verified Actions artifact without creating a GitHub release. A tag push, or an explicit
publish dispatch, creates a draft first. It downloads that draft's assets into a fresh directory,
repeats manifest and signature verification, compares every byte with the qualified stage, and only
then removes draft status. A failed readback leaves an unpublished draft for inspection.

## Manifest, SBOM, and provenance

`scorchkit-release-manifest.json` is canonical compact JSON conforming to
`release/scorchkit-release-manifest.schema.json`. It accounts for each target exactly once and binds
the package version, tag, source repository, full revision, Rust toolchain, feature set, source date,
binary size and SHA-256, and exact SBOM name and SHA-256.

Each binary has one canonical CycloneDX 1.6 document named `ASSET.cdx.json`. Syft 1.50.0 reads the
exact staged binary; the qualifier replaces time, serial, component, and binary-reference metadata
with deterministic release values before hashing. Consumers, the manifest, provenance, signing,
and publication all use those same staged bytes.

`scorchkit-provenance.intoto.json` is an in-toto Statement v1 with a SLSA provenance v1 predicate.
It binds every binary, SBOM, and the release manifest to the exact Git commit, workflow identity,
toolchain, feature set, targets, and invocation. `SHA256SUMS` covers those subjects and is itself
signed.

## Signature verification

Cosign 3.1.2 creates one keyless Sigstore bundle beside every binary, SBOM, manifest, checksum
document, and provenance statement. The certificate identity for tag `TAG` is:

```text
https://github.com/Ignibyte/scorch_kit/.github/workflows/release.yml@refs/tags/TAG
```

The verifier requires that exact identity, the GitHub OIDC issuer, and the release's full workflow
SHA. Cosign v3 removed the former `--offline` option. Network-independent verification instead uses
the bundle's embedded certificate/transparency proof and the checksum-pinned
`sigstore-trusted-root.json` installed by the release qualifier:

```bash
cosign verify-blob ASSET \
  --bundle ASSET.sigstore.json \
  --trusted-root sigstore-trusted-root.json \
  --certificate-identity "https://github.com/Ignibyte/scorch_kit/.github/workflows/release.yml@refs/tags/TAG" \
  --certificate-oidc-issuer "https://token.actions.githubusercontent.com" \
  --certificate-github-workflow-sha FULL_GIT_SHA
```

Verification fails for a changed subject, another workflow identity, another revision, a partial
bundle set, or a changed trusted root. The workflow proves those negative cases before publication.

## Upgrade and restore rehearsal

The first supported upgrade boundary is v2.1.0. Before upgrading an installation:

1. Verify the new release and record the current configuration, binary version, database identity,
   and PostgreSQL version.
2. Take a custom-format `pg_dump`, hash it, and test `pg_restore` into a separately named disposable
   database. Do not restore over the source database.
3. Run `scorchkit db migrate` against another restored rehearsal database and compare project,
   target, engagement, job, finding, evidence, and history identities.
4. Upgrade the intended database only after the rehearsal passes and keep the verified snapshot
   until the operational acceptance window closes.

ScorchKit does not ship destructive down migrations. Rollback means stopping the upgraded process
and restoring the verified pre-upgrade snapshot into a new database, then switching the operator's
explicit connection after identity checks. The repository integration fixture applies the exact
v2.1.0 migration ledger, injects a failing rehearsal, restores to a different disposable database,
and proves canonical identity/history parity.

## Operational budgets

Qualification rejects a binary larger than 150 MiB or a native `scorchkit --version` invocation
that takes longer than two seconds. Existing executor contracts retain their two-second bounded
cancellation, output-overflow, and descendant cleanup behavior. Every native target job has one
45-minute deadline, matrix failures fail fast, and no release job retries a failed build or check.

These are hard ceilings, not performance claims. A release candidate that exceeds one must be
diagnosed and deliberately redesigned; the workflow does not weaken, retry, or baseline the failure.
