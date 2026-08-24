---
title: INTAKE-reproducible-releases
status: promoted
created: 2026-08-17
ticket: TICKET-026
pipeline_spec: docs/planning/pipeline/completed/reproducible-releases.spec.md
---

# Reproducible signed releases provenance and rollback

## Problem or opportunity

ScorchKit does not yet prove clean-checkout reproducibility, publish its own signed SBOM and build
provenance, verify upgrade compatibility, or exercise rollback and resource budgets.

## Proposed outcome

Each ScorchKit release will be reproducible from a clean checkout, accompanied by signed artifacts,
SBOM and provenance attestations, and validated through upgrade, rollback, performance, and failure
budgets.

## Candidate EARS requirements

| ID | EARS Requirement | Verification |
|---|---|---|
| REQ-001 | When a release candidate is built twice from the same clean revision and declared environment, ScorchKit shall produce matching artifact identities or a documented deterministic equivalence. | Independent clean-build comparison. |
| REQ-002 | When release artifacts are published, ScorchKit shall include verified SBOM, provenance, digest, and signature material tied to the exact revision and toolchain. | Attestation verification tests. |
| REQ-003 | When a supported prior release is upgraded, ScorchKit shall migrate configuration and storage without losing target, engagement, job, finding, or evidence identity. | Upgrade fixture matrix. |
| REQ-004 | When rollback is invoked after a failed release or migration rehearsal, ScorchKit shall return to a documented recoverable state. | Disposable database and artifact rollback tests. |
| REQ-005 | When release validation runs, ScorchKit shall enforce reviewed performance, cancellation, output, and failure-injection budgets. | Release gate benchmark and chaos evidence. |

## Scope notes

- In: ScorchKit release artifacts, clean builds, SBOM, provenance, signing, upgrades, rollback,
  performance and chaos budgets.
- Out: target-application SBOM generation, deployment of user applications, weakening ordinary gates.
