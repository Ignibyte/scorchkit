---
title: Add reproducible releases and operational quality budgets — notes
pipeline_id: 86d039ec-9f07-4dad-9fa8-270799cb4ca7
---

# Add reproducible releases and operational quality budgets — running notes

Chronological and append-only. Record decisions, evidence, dead ends, and corrections.

## Phase 1 — Plan

- Recalled knowledge:
  - `AAR-012-application-supply-chain`, `PR-scorchkit-single-verified-sbom-001`, and
    `PR-scorchkit-verified-artifact-single-read-001`: generate, validate, and hash one bounded SBOM
    for each exact binary subject; do not recatalog bytes between provenance and publication.
  - `PR-scorchkit-durable-canonical-parity-001` and `PR-scorchkit-transition-audit-reconstruction-001`:
    the v2.1.0 upgrade fixture must compare canonical identities and histories, not merely row counts.
  - `PR-scorchkit-validation-evidence-before-receipt-001`: populate release evidence before the
    receipt-producing gate and reserve archive outcomes for the required delivery rerun.
  - `AAR-020-post-release-platform-roadmap`: SK-048 closes release prerequisites before the control
    API and extension sequence; it does not implement those later surfaces.
  - Official GitHub/Sigstore/Rust guidance: use full-commit action pins, least workflow permissions,
    short-lived OIDC signing identity, verifiable bundles, immutable release staging, and Rust source
    path remapping. GitHub artifact attestations are additive because private-repository entitlement
    is not assumed.
- Recon evidence:
  - No release workflow, toolchain pin, release manifest, signing bundle, or clean-build comparator
    exists. CI currently selects moving `stable` and action tags.
  - Supported production features are `infra cloud mcp`; supported hosts yield four release targets:
    Linux x86-64, macOS x86-64/Arm64, and Windows x86-64.
  - Local versions are Rust/Cargo 1.96.0 and the already-reviewed Syft 1.50.0. Existing release tags
    are v1.0.0 and v2.1.0; v2.1.0 is the compatibility baseline.
  - Existing executor tests already prove two-second timeout, cancellation, output-overflow, and
    descendant cleanup boundaries. The current debug CLI starts `--version` in 0.01 seconds.
- Operator confirmation: on 2026-08-23 the repository owner directed the completed survivor repair
  to move immediately to the next ordered ticket, SK-048. The existing supported-host, production-
  feature, latest-tag, immutable-evidence, and no-destructive-migration contracts resolve planning
  choices without authorizing a live release.

## Phase 2 — Design

- Architecture:
  - Added one repository-owned release qualifier and one declarative policy. Four native runners
    perform two path-remapped, locked, stripped builds of the same revision and compare bytes only
    within the same target/toolchain environment. One Linux aggregate job consumes the exact
    uploaded bytes, creates one Syft CycloneDX SBOM per binary, and binds binaries/SBOMs in a
    canonical manifest, SLSA provenance, and checksum document.
  - Cosign 3.1.2 keyless bundles cover every publication subject. Offline verification requires the
    exact release workflow identity, GitHub OIDC issuer, workflow SHA, bundled transparency proof,
    and checksum-pinned local Sigstore trusted root. Cosign v3.1.2 no longer exposes `--offline`;
    explicit `--trusted-root` is its supported network-independent verifier. The workflow tests
    tamper, wrong-identity, and wrong-revision rejection before draft publication.
  - Upgrade proof uses a representative v2.1.0 config plus exact migrations 001-004 and seeded
    stable rows. It hashes a pre-upgrade custom dump, migrates one disposable database forward,
    injects failure into another rehearsal, restores the verified snapshot into a third separately
    named database, and compares identities/history without a down migration.
  - Permissions default to read-only. Only the aggregate job gets `id-token: write` and
    `contents: write`; tool downloads are exact-version/checksum official assets; release creation
    is draft-first and absent from dry runs.
- File manifest: `rust-toolchain.toml`, `release/{policy.json,
  scorchkit-release-manifest.schema.json}`, `bin/release.sh`,
  `.github/workflows/{ci.yml,release.yml}`, `tests/{release_contract.rs,release_upgrade.rs}`,
  `tests/fixtures/release/v2.1.0/*`, `bin/gate.sh`, `tests/quality_gate_contract.rs`,
  `docs/guide/releases.md`, and the durable README/security/changelog/roadmap/planning artifacts.
- Regression test plan: release-script adversarial selftest; Rust policy/schema/workflow/package
  contract; current config loader fixture; live disposable PostgreSQL forward/failed/restore
  integration; local Linux double-build/dry assembly where available; existing lifecycle budgets;
  FAST development gate; and only database-backed DIFF validation/delivery.
- Current primary-source pins: checkout v6.0.2
  `de0fac2e4500dabe0009e67214ff5f5447ce83dd`, upload-artifact v7.0.1
  `043fb46d1a93c77aae656e7c1c64a875d1fc6a0a`, download-artifact v8.0.1
  `3e5f45b2cfb9172054b4087a40e8e0b5a5461e7c`; Cosign 3.1.2 Linux amd64 SHA-256
  `f7622ed3cf22e55e1ae6377c080979ff77a22da9981c11df222a2e444991e7cf`; Syft 1.50.0 archive
  SHA-256 `bf7b29ff57f06da30918266a0e1c2885a8f99784798d1bdb1628886aa015d788`.
- Operator confirmation: on 2026-08-23 the owner directed the next roughly five tickets to proceed
  and explicitly required DIFF-only mutation validation. That direction confirms this design and
  forbids a FULL/no-argument gate; it does not authorize a live release or push.

## Phase 3 — Implement

- Files and behavior changed:
  - Added the exact Rust 1.96.0 toolchain pin, release policy, closed manifest schema, and
    `bin/release.sh` qualifier. The qualifier rejects invalid source state, builds twice in
    isolated trees, verifies the declared native binary format/architecture, enforces size and
    startup budgets, assembles one exact subject inventory, produces per-binary CycloneDX SBOMs
    and SLSA/in-toto provenance, and verifies keyless bundles plus adversarial negatives.
  - Added a four-native-runner, full-action-SHA GitHub workflow with read-only defaults, bounded
    jobs, draft-first publication, exact artifact readback, and no retry path. Removed moving Rust
    selectors from ordinary CI so the repository toolchain file controls every job.
  - Added release policy/schema/workflow tests and a v2.1.0 config/PostgreSQL fixture that proves
    forward migration, deliberate rehearsal failure, verified snapshot restoration into a third
    database, and preservation of stable identities and nested history.
  - Wired the release selftest into gate 9 and documented qualification, consumer verification,
    raw-binary installation, upgrade rehearsal, and restore boundaries.
  - Local executable evidence: the pinned Linux target built twice from distinct clean source and
    target directories in 83 seconds per build; both 40,077,480-byte outputs had SHA-256
    `6f57ba4bc1699a35f1908e5918ae125d83e2743291404b870311f5a7a8ba7eed` and were byte-identical.
    `file`/`readelf` identified the output as a stripped x86-64 ELF PIE. The exact pinned Syft,
    Cosign, and trusted-root downloads passed their digest/version checks.
  - Focused contract tests passed (6 release contracts and 3 upgrade tests). The live upgrade test
    passed against the local PostgreSQL validation service, observed the injected division error,
    left no disposable databases behind, and the temporary local role privilege was revoked.
  - `bash bin/gate.sh --fast` initially found only a Taplo format drift and a spelling false
    positive for the standard `.intoto.json` suffix. Both were fixed at source; all other fast
    lanes were already green.
- Design deviations:
  - Cosign 3.1.2 has no legacy `--offline` option. Network-independent verification therefore uses
    the exact checksum-pinned local Sigstore trusted root through `--trusted-root`, while retaining
    bundled transparency proof and exact identity/revision checks.
  - Aggregate qualification now parses ELF, PE, and Mach-O headers instead of trusting filenames.
    A local assembly experiment using copied Linux bytes under all four target names exposed this
    otherwise-valid substitution gap; the selftest now generates target-specific headers and
    proves cross-target rejection.

## Phase 3.5 — Inspect ledger

| # | Critic | Finding | Severity | Disposition |
|---|---|---|---|---|
| 1 | Correctness | Cargo metadata preflight ran from the caller's directory, and the matrix installed targets against the runner default rather than explicitly against Rust 1.96.0. | High | Fixed: preflight changes into the qualified checkout, and both preflight/matrix installation name the exact policy toolchain; workflow contract added. |
| 2 | Security | Executable-header validation read the entire subject before enforcing the 150 MiB ceiling. | Medium | Fixed: read only the first 512 bytes needed for ELF/PE/Mach-O parsing. |
| 3 | Data integrity | Consumer/readback verification trusted assembly-time checks for architecture and size and verified only a subset of SLSA parameters; its build-type URI also pointed at mutable `main`. | High | Fixed: recheck architecture/budget/Syft identity, compare the complete external parameters/dependency/builder/invocation shape, bind build type to the immutable revision, and add a provenance-drift negative. |
| 4 | Recovery | Passwords were removed from SQLx URLs, any nonzero `psql` result could masquerade as the injected failure, partial setup could leak databases, and snapshot integrity was checked only after restore. | High | Fixed: preserve credentials for SQLx while stripping them only from subprocess argv, prove the failure marker committed, cleanup every attempted name with observable errors, verify the snapshot before and after restore, and assert exact current/restored migration ledgers. |
| 5 | Simplification | Checksum generation was duplicated between assembly and adversarial tests. | Low | Fixed: extracted one `write_checksums` path used by both. |

## Phase 4 — Validate

- Tests run (commands and outcomes):
  - `shellcheck -x bin/release.sh` and `bash bin/release.sh --selftest`: PASS, including malformed
    source state, exact inventory, target-format substitution, manifest duplication, provenance
    parameter drift, and tampered-subject rejection.
  - `cargo test --all-features --test release_contract --test release_upgrade`: PASS (6 release
    contracts, 3 upgrade contracts); focused Clippy with `-D warnings`: PASS.
  - Live `DATABASE_URL=postgresql:///scorchkit_codex_validation_001 cargo test --all-features
    --test release_upgrade -- --nocapture`: PASS; the deliberate division-by-zero failure was
    observed, all three disposable databases were removed, and temporary `CREATEDB` was revoked.
  - `actionlint -ignore 'label "macos-15-intel" is unknown' .github/workflows/release.yml
    .github/workflows/ci.yml`: PASS. The narrow ignore compensates for local actionlint 1.7.7's
    stale runner-label catalog; the official standard runner contract supports that label.
  - `bash bin/mutants.sh --inspect`: PASS; 9,772 configured mutants across 298 workspace source
    files, composition binary excluded, policy kernel included. This inspection compiles no mutant.
  - The first DIFF attempt was interrupted before mutation compilation after crates.io timed out in
    `cargo-audit`; a direct audit rerun passed with the five already-reviewed allowed warnings.
- Gate run and receipt: pre-completion
  `DATABASE_URL=postgresql:///scorchkit_codex_validation_001 bash bin/gate.sh --diff` was GREEN:
  19 passed, 0 failed, and 3 named web-only skips. Coverage was 82.13%; Nextest passed 1,954 cases
  with 10 reasoned live-tool/network skips. The DIFF mutation selection completed with explicit
  empty evidence (0 viable/missed/timeout/unviable, 100% MSI). No FULL/no-argument mutation mode ran.
- Documented skips with reasons:
  - No live tag, GitHub release, OIDC signature, draft, or publication was created; those are
    explicitly outside implementation authority and remain executable workflow evidence.
  - macOS x86-64/Arm64 and Windows x86-64 native builds were not emulated on Linux. Their exact
    runner/target contracts are statically validated; native execution occurs only in the bounded
    release matrix.

## Phase 5 — Complete

- Docs updated: README installation/release support, SECURITY release and recovery invariants,
  CHANGELOG SK-048 entry, release operator guide, and ROADMAP completion/evidence/next-ticket state.
- AAR submitted: `AAR-026-reproducible-releases`, effectiveness 4/5, with four failure patterns and
  four prevention rules registered in the knowledge index.
- Archive: TICKET-026 closed on 2026-08-23 and the spec/notes moved to the completed pipeline store.
  Delivery reruns the same DIFF gate because archival invalidated the validation receipt.

## Defect and lesson ledger

| # | What broke | Root cause | Fix | Prevention |
|---|---|---|---|---|
| 1 | Initial legacy database fixture could not run current migrations. | It recreated schema objects but omitted SQLx's migration ledger and exact prior checksums. | Added migrations 001-004 to `_sqlx_migrations` with their exact SHA-384 checksums. | Legacy upgrade fixtures must reproduce migration provenance, not only visible tables and rows. |
| 2 | A copied Linux binary could initially stand in for every target during aggregate assembly. | Artifact filenames and digests were checked, but executable headers were not bound to target triples. | Parse and require exact ELF/PE/Mach-O architecture/type before build acceptance and assembly. | Treat platform format and architecture as signed subject identity inputs. |
| 3 | The first fast gate rejected release metadata formatting/spelling. | The new toolchain file had not been Taplo-formatted and `intoto` was absent from the exact-word dictionary. | Formatted the file and added the standard provenance suffix to `typos.toml`. | Run the metadata-format lane after adding repository-owned formats and standard artifact names. |
| 4 | Native target installation could attach to a moving runner default. | The workflow executed `rustup target add` outside either checkout, so the repository override was not active. | Install the target and required components against the exact policy toolchain. | Toolchain selection must be explicit at every pre-build effect, not inferred from a later Cargo working directory. |
| 5 | Credentialed PostgreSQL rehearsals would fail or be misclassified. | One sanitizing helper removed passwords from both subprocess and SQLx URLs, while expected-failure logic checked only a nonzero exit. | Split runtime/tool URLs and verify the committed failure marker. | Expected-failure tests must prove the intended state transition, not merely observe an error status. |
| 6 | Restore verification occurred after `pg_restore`. | The digest comparison was ordered after the effect it was meant to authorize. | Verify the snapshot digest immediately before restore and again afterward. | Integrity predicates must precede the effect they gate. |
