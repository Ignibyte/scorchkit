---
title: INTAKE-extension-catalog
status: candidate
created: 2026-08-21
ticket:
pipeline_spec:
---

# Signed extension catalog and lifecycle

## Problem or opportunity

An extension SDK and isolated runtime do not answer how users discover compatible modules, review
new permissions, verify publisher provenance, pin versions, receive revocations, or roll back a bad
upgrade. Automatic or ambient installation would turn scanner supply-chain state into an
unreviewed execution path.

## Proposed outcome

ScorchKit can consume a signed, versioned application-security extension catalog with explicit
permission review, compatibility and conformance evidence, exact digest pinning, upgrade/rollback,
and revocation behavior. Local offline catalogs remain supported.

## Candidate EARS requirements

| ID | EARS Requirement | Verification |
|---|---|---|
| REQ-001 | When catalog metadata or an extension artifact is accepted, ScorchKit shall verify its signature, publisher identity, digest, provenance, compatibility range, and conformance result before registration. | Signature, tamper, wrong-publisher, digest, compatibility, and conformance tests. |
| REQ-002 | When an install or upgrade adds or widens a capability, effect, endpoint, credential, filesystem, subprocess, or resource request, ScorchKit shall present the exact permission difference and require explicit approval before activation. | Permission-diff and no-approval denial tests. |
| REQ-003 | When an extension version is activated, ScorchKit shall pin its manifest and artifact identities in every invocation and shall not replace it through an ambient or moving reference. | Pinning, cache, restart, and invocation-provenance tests. |
| REQ-004 | When an extension is revoked, ScorchKit shall block new invocations, preserve historical evidence and provenance, expose the reason, and require a separate reviewed action before any replacement runs. | Revocation and historical-read tests. |
| REQ-005 | When an upgrade fails compatibility, conformance, startup, or health checks, ScorchKit shall retain or restore the last approved version without losing configuration or evidence identity. | Upgrade/rollback and failure-injection matrix. |
| REQ-006 | When a catalog is unavailable, ScorchKit shall continue to operate with exact locally approved extensions and shall not disable built-in application-security capabilities or fetch from an undeclared source. | Offline and endpoint-denial tests. |

## Scope notes

- In: signed catalog metadata, publisher provenance, exact artifacts, permission review,
  compatibility, conformance, pinning, upgrade, rollback, revocation, offline catalogs.
- Out: silent auto-update, unsigned moving references, public catalog hosting, payment/licensing, or
  non-application-security categories in default profiles.
