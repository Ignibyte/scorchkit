---
title: TICKET-026-reproducible-releases
status: done
ticket_number: 026
type: feature
created: 2026-08-23
closed: 2026-08-23
intake: docs/planning/intake/INTAKE-reproducible-releases.md
pipeline_spec: docs/planning/pipeline/completed/reproducible-releases.spec.md
---

# Add reproducible releases and operational quality budgets

## Summary

Ship a fail-closed release qualification and publication path for the supported ScorchKit binary on
Linux, macOS, and Windows. A semver tag will identify immutable raw binaries, checksums, an SBOM,
signed provenance, and a release manifest; local fixtures will prove upgrade/restore compatibility
and enforce reviewed artifact, startup, cancellation, output, and failure budgets.

## Why

SK-033 stabilized the workspace boundary, SK-035 stabilized durable evidence identity, SK-046
retired release-blocking dependency debt, and SK-047 closed its exact mutation repair. The project
still has only source-build instructions and a moving `stable` CI toolchain. SK-048 is the final
prerequisite before the post-release control API and extension sequence.

## EARS Requirements

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

## Scope

- In: pinned production toolchain/features; Linux x86-64, macOS x86-64/Arm64, and Windows x86-64
  raw binary assets; deterministic double builds; checksums; CycloneDX SBOM; signed in-toto/SLSA
  provenance; draft-first GitHub release workflow; v2.1.0 upgrade and disposable-database restore
  fixtures; bounded release qualification.
- Out: executing a real release from this ticket, package registries, containers, installers,
  auto-update, OS-native Authenticode/notarization, long-lived signing keys, target-application
  SBOMs, production database rollback, destructive down migrations, deployment, or weaker gates.

## Locked decisions

- Distribute the supported production feature set `infra cloud mcp`; quarantined native cloud SDK
  features are not release defaults.
- Compare byte identity only within the same declared target/toolchain environment. Cross-platform
  binaries are distinct expected subjects and share one canonical release manifest.
- Publish raw target-named binaries rather than nondeterministic archives. Unix installation must
  preserve or restore executable permission explicitly.
- Use short-lived OIDC/Sigstore identity and verification bundles; no repository or operator holds
  a long-lived release-signing secret. GitHub artifact attestations may be additive but cannot be
  the sole signature because this repository's plan/visibility entitlement is not assumed.
- Treat rollback as verified snapshot restoration into a separate destination. ScorchKit does not
  run destructive down migrations against an upgraded database.
- Use v2.1.0, the latest existing release tag, as the first supported upgrade fixture.
- Validate and deliver this ticket with `bash bin/gate.sh --diff` only. The owner explicitly
  prohibited a no-argument/FULL mutation run for this ticket and the following platform tickets.

## Recon

- The repository supports Linux, macOS, and Windows but has no release workflow, release manifest,
  pinned Rust toolchain file, or binary publication contract. Existing CI uses moving `stable` and
  action tags.
- The current host uses Rust/Cargo 1.96.0; Syft 1.50.0 is already the reviewed exact SBOM producer.
  The debug CLI reports version 3.0.0 in 0.01 seconds, leaving ample headroom for a two-second
  release-binary startup budget.
- Existing tags are v1.0.0 and v2.1.0. v2.1.0 owns migrations 001–004; current 3.0.0 adds migrations
  005–012 and stable job, evidence, attack-path, and webhook identities.
- Official GitHub guidance requires minimum `id-token`/attestation permissions and recommends
  full-commit action pins. GitHub's current first-party `actions/attest` v4 signs provenance and
  CycloneDX/SPDX statements, but private-repository availability depends on Enterprise Cloud.
  Sigstore Cosign 3.1.2 provides the independent bundle-based keyless path.

## Notes

- Active pipeline: `docs/planning/pipeline/completed/reproducible-releases.spec.md`

## Log

- 2026-08-23: opened.
- 2026-08-23: promoted from `INTAKE-reproducible-releases` after the owner directed work to move
  from the closed survivor repair to the next ordered ticket.
- 2026-08-23: the owner directed work to continue through roughly SK-052 and required ordinary
  DIFF mutation selection rather than a FULL campaign for every ticket in that sequence.
- 2026-08-23: implementation, adversarial inspection, and validation completed. The DIFF gate
  passed 19 applicable lanes with an explicit empty mutation selection; no live release or broad
  mutation campaign ran. Completion submitted AAR-026 and advanced the roadmap to SK-049.
