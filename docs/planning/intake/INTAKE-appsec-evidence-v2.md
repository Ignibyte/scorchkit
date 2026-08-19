---
title: INTAKE-appsec-evidence-v2
status: candidate
created: 2026-08-17
ticket:
pipeline_spec:
---

# Versioned application-security observations evidence and finding identity

## Problem or opportunity

The shared finding model flattens file locations, HTTP exchanges, dependency identities, scanner
provenance, and agent analysis into optional strings. That prevents reliable deduplication,
source-to-runtime correlation, redaction, migration, and focused verification.

## Proposed outcome

ScorchKit will have versioned observation, evidence, finding, and correlation identities capable of
representing source flows, application requests, authentication personas, packages, artifacts, and
scanner provenance without mixing raw evidence with agent interpretation.

## Candidate EARS requirements

| ID | EARS Requirement | Verification |
|---|---|---|
| REQ-001 | When a scanner publishes an observation, ScorchKit shall encode its source, runtime, package, or artifact location in a typed versioned location rather than a display string. | Schema round-trip and legacy migration fixtures. |
| REQ-002 | When evidence is captured, ScorchKit shall retain scanner, version, rule or template digest, configuration identity, target revision, and collection time. | Cross-scanner provenance golden tests. |
| REQ-003 | When HTTP evidence is stored or reported, ScorchKit shall preserve the redacted request, response, route, parameter, and authentication-persona identity needed for reproduction. | Loopback evidence and secret-redaction tests. |
| REQ-004 | When equivalent observations arrive from multiple scanners, ScorchKit shall calculate a stable identity without discarding distinct raw evidence. | Deduplication and collision fixtures. |
| REQ-005 | When agent analysis is attached, ScorchKit shall label it separately from immutable scanner evidence and preserve both through JSON, SARIF, storage, and reports. | Cross-format golden tests and database round trips. |

## Scope notes

- In: schema versioning, compatibility readers, identities, provenance, typed locations, redaction,
  storage and report migrations.
- Out: scanner-specific deep integrations, automated exploit execution, changes to authorization.
