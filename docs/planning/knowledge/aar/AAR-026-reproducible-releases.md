---
aar: AAR-026-reproducible-releases
ticket: TICKET-026
pipeline: reproducible-releases
status: submitted
opened: 2026-08-23
submitted: 2026-08-23
effectiveness: 4
---

# AAR-026 — Add reproducible releases and operational quality budgets

## Recalled at plan

| ID or source | How it surfaced | Useful? |
|---|---|---|
| `AAR-012-application-supply-chain` / `PR-scorchkit-single-verified-sbom-001` | Release SBOM and provenance must describe the exact shipped binary. | Yes; use one validated bounded SBOM per binary and bind it in the canonical release manifest. |
| `PR-scorchkit-verified-artifact-single-read-001` | Signing and publication could reopen or recatalog different bytes. | Yes; verification, provenance, and publication consume the same staged subject identity. |
| `PR-scorchkit-durable-canonical-parity-001` / `PR-scorchkit-transition-audit-reconstruction-001` | Upgrade compatibility could be reduced to table or row counts. | Yes; compare stable identities, raw canonical records, and append-only histories. |
| `PR-scorchkit-validation-evidence-before-receipt-001` | Release evidence and pipeline documents change the exact worktree. | Yes; sequence tracked evidence before validation and final archive proof before delivery. |
| `AAR-020-post-release-platform-roadmap` | SK-048 is the boundary before later API and extension work. | Yes; keep later platform surfaces and deployment out of release hardening. |
| Official GitHub artifact-attestation and workflow-hardening guidance | Signing and action versions are temporally sensitive. | Yes; use least permissions, full-SHA action pins, OIDC identity, verifiable bundles, and draft-first publication. |
| Official Rust source-remapping guidance | Distinct clean source paths can leak into binaries. | Yes; remap absolute and relative paths before requiring byte identity. |
| Owner DIFF-only direction | The next platform tickets must not trigger another broad mutation campaign. | Yes; validation and post-archive delivery use only `gate.sh --diff`; the release workflow never runs mutation testing. |

## What happened

- Planning promoted SK-048 as TICKET-026 after TICKET-025's survivor-only delivery. The repository
  now pins Rust 1.96.0 and one `infra,cloud,mcp` release policy, double-builds raw binaries on four
  native targets, parses their ELF/PE/Mach-O identities, and assembles one exact manifest,
  checksums, per-binary CycloneDX SBOMs, and immutable-revision SLSA provenance.
- The GitHub workflow pins action commits and release tools, grants OIDC/release writes only to the
  aggregate job, signs every published subject with keyless Cosign bundles, proves identity/SHA/
  tamper negatives, creates a draft, reads every asset back, and publishes only after byte parity.
  No live tag, signature, draft, or release was created during the ticket.
- A v2.1.0 fixture now proves current config compatibility, exact SQLx history, stable identity and
  nested-history preservation, intended migration failure, pre-effect snapshot verification, and
  restore into a separate database at the exact v2.1.0 ledger. Credentialed and peer-auth database
  URLs follow separate SQLx/subprocess handling without exposing passwords on process arguments.
- Local Linux builds from two clean source/target paths produced identical 40,077,480-byte stripped
  x86-64 ELF PIEs with SHA-256
  `6f57ba4bc1699a35f1908e5918ae125d83e2743291404b870311f5a7a8ba7eed`. The final DIFF gate passed
  19 lanes at 82.13% line coverage and 1,954 strict cases; its completed mutation selection was
  explicitly empty (0 viable/missed/timeout/unviable, 100% MSI), so no broad campaign ran.

## Novel findings

- GitHub's first-party artifact attestations are not universally available to private repositories;
  the release contract therefore needs independently verifiable Sigstore bundles rather than an
  entitlement-dependent sole signature.
- Publishing raw target-named binaries removes archive timestamp/permission metadata from the
  reproducibility denominator. Unix installation must explicitly restore executable permission.
- A target-shaped filename and correct digest do not prove platform identity. Aggregate
  verification must parse the executable header and bind architecture/type before signing.
- Cosign 3.1.2 removed the legacy `--offline` switch. Network-independent bundle verification uses
  a checksum-pinned local Sigstore trusted root plus the embedded transparency proof and exact
  GitHub workflow identity/revision.
- SQLx upgrade fixtures must recreate the exact prior migration ledger and checksums; copying only
  schema objects and rows makes the current embedded migrator reject an otherwise plausible legacy
  database.
- An expected-failure rehearsal is valid only when it proves the intended pre-failure state
  transition. Treating any nonzero subprocess status as the injection would accept authentication,
  connection, and syntax failures as recovery evidence.

## Failures captured

| ID | Failure | Where it surfaced |
|---|---|---|
| `BF-scorchkit-release-filename-platform-substitution-001` | Aggregate assembly initially accepted copied Linux bytes under all four policy filenames because it bound name/digest but not executable architecture. | Local dry assembly during implementation. |
| `BF-scorchkit-release-runner-default-toolchain-001` | Native target installation ran outside the checkouts and could attach to the hosted runner's moving default toolchain rather than Rust 1.96.0. | Correctness inspection of the release workflow. |
| `BF-scorchkit-postgres-expected-error-conflation-001` | One helper stripped passwords from SQLx URLs, and a generic nonzero `psql` exit could masquerade as the deliberate division failure. | Recovery inspection and credentialed-URL unit contract. |
| `BF-scorchkit-snapshot-post-effect-verification-001` | The first restore path compared the snapshot digest only after `pg_restore`, too late to gate the recovery effect. | Data-integrity inspection of the upgrade fixture. |

## Prevention rules captured

| ID | Rule | Why |
|---|---|---|
| `PR-scorchkit-release-target-header-binding-001` | Bind a release subject's target name and digest to a parsed bounded ELF, PE, or Mach-O format/architecture check at native build, aggregate assembly, and consumer readback. | Filenames and checksums can faithfully identify the wrong platform bytes. |
| `PR-scorchkit-release-toolchain-effect-pin-001` | Select the exact release toolchain for metadata resolution, component/target installation, and compilation; do not infer it from a later working directory. | A runner default can move or receive the target while the pinned compiler remains unprepared. |
| `PR-scorchkit-expected-failure-transition-proof-001` | Expected-failure integration tests must observe the intended committed marker or state transition in addition to a failure status. | Authentication, transport, parser, and injection failures can otherwise collapse into the same false-positive result. |
| `PR-scorchkit-restore-integrity-before-effect-001` | Verify a snapshot's recorded identity immediately before restore and again after consumption, and restore only into a separately bounded destination. | An integrity check performed only after the effect cannot authorize safe recovery. |

Every new ID must also be added to `docs/planning/knowledge/INDEX.md`.

## Effectiveness

Score: 4/5. Recalled SBOM single-read identity, canonical parity, workflow hardening, and receipt
sequencing directly shaped the delivered subject graph, recovery fixture, and DIFF-only validation.
Adversarial inspection still found four consequential gaps—platform substitution, ambient
toolchain selection, credential/error conflation, and post-effect snapshot verification—so the
initial design was not complete enough for a perfect score. Each gap now has an executable negative
or state assertion and a reusable prevention rule.
