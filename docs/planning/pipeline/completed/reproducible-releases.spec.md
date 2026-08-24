---
title: Add reproducible releases and operational quality budgets
pipeline_id: 86d039ec-9f07-4dad-9fa8-270799cb4ca7
status: Phase 5 — Complete PASS; ready for delivery
ticket: TICKET-026
ticket_doc: docs/planning/tickets/closed/TICKET-026-reproducible-releases.md
aar: docs/planning/knowledge/aar/AAR-026-reproducible-releases.md
created: 2026-08-23
---

# Add reproducible releases and operational quality budgets — spec

## Intent

Deliver the repository-owned contracts needed to produce, verify, stage, and safely recover a
ScorchKit 3.x release: deterministic supported-platform binaries, exact artifact identities,
CycloneDX SBOM and signed provenance, upgrade/restore compatibility, and bounded operational
qualification. No release is published while implementing the ticket.

## Scope

- In: pinned production toolchain/features; Linux x86-64, macOS x86-64/Arm64, and Windows x86-64
  raw binary assets; deterministic double builds; checksums; CycloneDX SBOM; signed in-toto/SLSA
  provenance; draft-first GitHub release workflow; v2.1.0 upgrade and disposable-database restore
  fixtures; artifact/startup/cancellation/output/failure budgets; documentation.
- Out: live publication, package registries, containers, installers, auto-update, platform-native
  code signing/notarization, long-lived keys, target-application SBOMs, deployment, production
  database rollback, destructive down migrations, or quality-gate weakening.

## Acceptance criteria (EARS)

| ID | EARS Requirement | Verification |
|---|---|---|
| REQ-001 | When release qualification receives a tag or revision, ScorchKit shall reject a dirty, non-semver, version-mismatched, moving-toolchain, or unlocked source before producing a publishable manifest. | Release-script adversarial selftests and manifest/version contracts. |
| REQ-002 | When one supported target is built twice from the same clean revision in distinct source and target directories, ScorchKit shall produce byte-identical stripped binaries from the pinned Rust toolchain and production feature set. | Four-target clean-build matrix and digest comparison. |
| REQ-003 | When release artifacts are assembled, ScorchKit shall account for each expected target exactly once and shall bind its name, target, version, source revision, toolchain, features, size, SHA-256, and SBOM identity in one canonical manifest. | Manifest schema, missing/extra/duplicate/tamper tests, and release dry run. |
| REQ-004 | When a release candidate is signed, ScorchKit shall emit independently verifiable keyless Sigstore bundles for every binary, checksum/manifest document, SBOM, and provenance predicate, tied to the repository workflow identity and exact revision. | Offline bundle verification plus wrong-identity, wrong-revision, and tamper negatives. |
| REQ-005 | When a release workflow publishes, ScorchKit shall stage a draft, use minimum write permissions and full-SHA-pinned actions, verify every downloaded matrix artifact and signature, and publish only after the complete set passes. | Workflow static contract and non-publishing fixture simulation. |
| REQ-006 | When current ScorchKit upgrades the latest supported prior release fixture, it shall load its configuration and migrate PostgreSQL while preserving project, target, engagement, job, finding, and evidence identities and history. | Versioned v2.1.0 configuration/database upgrade fixture. |
| REQ-007 | When a migration rehearsal fails, ScorchKit shall restore a verified pre-upgrade snapshot into a separate disposable database and prove the prior schema and identities remain recoverable without a down migration. | PostgreSQL failure-injection and snapshot/restore test. |
| REQ-008 | When release qualification runs, ScorchKit shall enforce a 150 MiB per-binary ceiling, a two-second `--version` startup ceiling, existing two-second cancellation/output-overflow termination contracts, and a 45-minute per-target workflow deadline without retrying failures. | Release budget script, process lifecycle tests, and workflow contract. |

## Locked decisions

| # | Decision | Why |
|---|---|---|
| 1 | Release `infra cloud mcp`, not quarantined native cloud SDK features. | This is the documented supported production build and does not present unsealed providers as public defaults. |
| 2 | Build four target-named raw binaries and compare two builds within each target environment. | Raw assets avoid archive metadata nondeterminism; cross-platform bytes are intentionally distinct. |
| 3 | Use one canonical manifest and one exact SBOM per binary, with every published byte covered by SHA-256 and keyless Sigstore identity. | Consumers need one reconstructable subject set rather than duplicated, drifting metadata. |
| 4 | Stage a draft and publish only after aggregate verification; pin every action by full commit SHA. | Release write permission must not expose a partial or action-tag-substituted release. |
| 5 | Rehearse v2.1.0-to-current migration and snapshot restoration only in disposable databases. | v2.1.0 is the latest existing tag; down migrations would risk destroying evidence and identity. |
| 6 | Enforce generous hard ceilings rather than percentile microbenchmarks. | Artifact size, startup, and lifecycle deadlines are observable and stable enough for release gating. |
| 7 | Use only ordinary DIFF validation and delivery for this ticket. | The owner explicitly prohibited another no-argument/FULL mutation campaign while advancing the next platform tickets. |

## Architecture

The repository owns a fail-closed release qualifier under `bin/release.sh` and a declarative
`release/policy.json`. The policy is the single source for the four supported target triples,
target-named binary assets, exact production features, pinned Rust/Syft/Cosign versions, artifact
and startup ceilings, workflow deadline, and release workflow identity. The qualifier has separate
preflight, native double-build, assembly, verification, signature-verification, tool-install, and
selftest commands. Publication is never an implicit side effect of qualification.

Each native GitHub runner checks out the exact revision twice in different directories. Both builds
use the pinned toolchain, locked dependency graph, disabled incremental compilation, a fixed source
date, source/target path remapping, symbol stripping, and the exact `infra,cloud,mcp` feature set.
The job rejects unequal bytes, oversized output, or a `--version` process that exceeds two seconds,
then uploads one raw target-named binary. Cross-target bytes are intentionally not compared.

One Linux aggregate job downloads all four matrix artifacts into a new staging directory, rejects
missing, duplicate, symlinked, or unexpected subjects, and reads each binary once for its size and
SHA-256 identity. It uses the already-reviewed Syft 1.50.0 producer to create one canonicalized
CycloneDX 1.6 SBOM per exact binary. A canonical release manifest binds the complete target set,
version, revision, toolchain, features, size, binary digest, SBOM name, and SBOM digest. One SLSA
v1/in-toto statement binds those staged subjects and the exact workflow/revision; `SHA256SUMS`
covers every non-signature publication subject.

Cosign 3.1.2 signs every binary, SBOM, manifest, checksum document, and provenance statement with
the GitHub workflow's short-lived OIDC identity. Verification requires the exact workflow identity,
OIDC issuer, and GitHub workflow SHA, uses the transparency material embedded in each bundle plus a
checksum-pinned local Sigstore trusted-root document for network-independent verification, and
proves wrong-identity, wrong-revision, and tampered-subject negatives. Cosign v3 removed the legacy
`--offline` flag; the explicit `--trusted-root` path is its supported local verification boundary.
Only after aggregate verification may the workflow create a draft, upload the complete set, and
flip that draft to published. A dry-run dispatch never creates or edits a release.

Upgrade compatibility is fixture-owned. The current config loader reads a representative v2.1.0
configuration, and a database integration test creates uniquely named disposable databases,
installs the exact v2.1.0 schema and canonical identity/history rows, takes and hashes a custom
`pg_dump`, applies current embedded migrations, and compares exact identities and histories. A
deliberately failed rehearsal is restored from the verified snapshot into a different disposable
database and compared without invoking a down migration. Cleanup can drop only names carrying the
test's exact generated prefix.

## Security and compatibility boundaries

- Release tooling performs only repository, native build, GitHub artifact/release, Fulcio/Rekor,
  and checksum-verified official-tool effects declared by the workflow. It never scans a target.
- Workflow permissions default to `contents: read`; only the aggregate signing/publication job gets
  `id-token: write` and `contents: write`. Checkout does not persist credentials.
- Downloaded tools are exact-version, HTTPS-only, digest-verified assets installed under the job's
  temporary directory. No long-lived key or signing secret exists.
- Existing CLI, MCP, JSON, report, scanner, and storage APIs remain compatible. Release assets use
  raw files, so Unix consumers explicitly restore executable mode after download.
- Database fixtures never derive a drop target from operator input and never operate on the supplied
  validation database itself. A failed test leaves production schemas and migration history alone.
- The ordinary CI schedule remains separate from this release workflow. Ticket validation and
  post-archive delivery invoke `bash bin/gate.sh --diff`, never FULL/no-argument mode.

## File manifest

| Path | Change |
|---|---|
| `rust-toolchain.toml` | Add exact Rust 1.96.0 profile/components pin. |
| `release/policy.json` | Add the canonical target, feature, tool, workflow, and budget policy. |
| `release/scorchkit-release-manifest.schema.json` | Add the strict public release-manifest schema. |
| `bin/release.sh` | Add preflight, native reproducibility, assembly, verification, signing verification, exact tool installation, and selftests. |
| `.github/workflows/release.yml` | Add full-SHA-pinned four-target build and aggregate draft/sign/publish workflow. |
| `.github/workflows/ci.yml` | Remove moving Rust action selection so CI honors `rust-toolchain.toml`. |
| `tests/release_contract.rs` | Add policy, version, manifest, workflow, pin, negative, and script contracts. |
| `tests/release_upgrade.rs` | Add current-loader and disposable PostgreSQL upgrade/restore proof. |
| `tests/fixtures/release/v2.1.0/*` | Add exact legacy configuration, schema, canonical seed, and failure injection. |
| `bin/gate.sh`, `tests/quality_gate_contract.rs` | Wire the release selftest into the existing shell/static lane without adding or weakening a gate. |
| `docs/guide/releases.md` | Document qualification, verification, installation, upgrade, and restore operations. |
| `README.md`, `SECURITY.md`, `CHANGELOG.md`, `docs/planning/ROADMAP.md` | Update durable release support and evidence at completion. |
| ticket/spec/notes/AAR/knowledge index | Record phase evidence, inspection, lessons, and archive state. |

## Regression plan

1. Run `bash bin/release.sh --selftest` against temporary Git repositories and staged fixtures;
   cover dirty, malformed tag, version mismatch, moving toolchain, unlocked metadata, missing,
   extra, duplicate, symlink, checksum, SBOM, manifest, and tamper failures.
2. Run `cargo test --all-features --test release_contract` to pin the policy/schema/workflow,
   full-SHA actions, permissions, deadline, draft ordering, exact subjects, signature identity/SHA,
   no-retry behavior, and workspace package-version parity.
3. Run `cargo test --all-features --test release_upgrade` with the validation database available;
   prove v2.1.0 config compatibility, exact post-migration identity/history, injected failure,
   snapshot digest, separate restore destination, and cleanup safety.
4. Exercise a local Linux double build and dry-run assembly with the pinned tools where host
   resources permit; native macOS/Windows and both macOS architectures remain executable workflow
   matrix evidence rather than being emulated on Linux.
5. Preserve existing two-second cancellation, output-overflow, and descendant-cleanup suites.
6. Run `bash bin/gate.sh --fast` during implementation. Validate and deliver only with
   `DATABASE_URL=postgresql:///scorchkit_codex_validation_001 bash bin/gate.sh --diff`.

## Linked artifacts

- Ticket: `docs/planning/tickets/closed/TICKET-026-reproducible-releases.md`
- AAR: `docs/planning/knowledge/aar/AAR-026-reproducible-releases.md`
- Intake: `docs/planning/intake/INTAKE-reproducible-releases.md`
- Architecture:
  - `CONSTITUTION.md` sections 0, 3, 7, 14, 15, and 19
  - `SECURITY.md`
  - `docs/architecture/application-supply-chain.md`
  - `docs/architecture/storage.md`
  - `docs/planning/ROADMAP.md`

## Phase plan

| Phase | Deliverable | Exit evidence |
|---|---|---|
| 1 Plan | ticket, AAR, spec, notes, recalled knowledge | operator confirmation |
| 2 Design | architecture, file manifest, regression plan | operator confirmation |
| 3 Implement | code per design | self-review |
| 3.5 Inspect | adversarial ledger with dispositions | lead review |
| 4 Validate | tests run and delivery gate green | matching receipt |
| 5 Complete | docs, submitted AAR, archive, closed ticket | archive complete |
| Delivery | gate rerun after archive, commit/PR | matching receipt |
