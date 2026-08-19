---
title: TICKET-010-appsec-evidence-v2
status: done
ticket_number: 010
type: feature
created: 2026-08-19
closed: 2026-08-19
intake:
pipeline_spec: docs/planning/pipeline/completed/appsec-evidence-v2.spec.md
focused_repair: approved
focused_evidence: scorchkit-mutants-focused-ticket-010
---

# Version application-security evidence and finding identity

## Summary

Ship a versioned, agent-neutral application-security observation contract for findings, typed
locations, scanner provenance, redacted evidence, stable identity, correlation keys, and labeled
agent analysis. Preserve the existing `Finding` API and legacy JSON while making JSON, SARIF, and
PostgreSQL storage consume the same canonical v2 record.

## Why

SK-029 established provider-neutral AI contracts and SK-034 established application-security
adapter boundaries. ScorchKit now needs a durable boundary between immutable scanner observations
and later agent interpretation before deeper SAST/DAST integrations can safely share, correlate,
store, and report evidence.

## EARS Requirements

| ID | EARS Requirement | Verification |
|---|---|---|
| REQ-001 | When a finding is constructed or legacy finding JSON is read, ScorchKit shall expose a `scorchkit.finding/v2` record with a typed source, runtime, package, artifact, or legacy location without removing legacy fields. | Core constructor, serde migration, and round-trip tests. |
| REQ-002 | When scanner evidence is attached, ScorchKit shall retain scanner/version/rule-or-template/config/target-revision/collection-time provenance and assign a deterministic evidence identity. | Core provenance and identity tests; Semgrep and Nuclei parser tests. |
| REQ-003 | When HTTP evidence contains sensitive headers, query values, or keyed body values, ScorchKit shall redact them while retaining method, route, parameter identity, authentication persona identity, response status, and truncation state. | HTTP evidence redaction and serialization tests. |
| REQ-004 | When equivalent observations arrive from different scanners, ScorchKit shall produce the same stable finding identity while retaining distinct raw evidence records. | Cross-scanner core identity test and PostgreSQL integration test. |
| REQ-005 | When agent analysis is attached, ScorchKit shall label and serialize it separately from immutable scanner evidence in JSON, SARIF, and stored finding records. | Core/JSON/SARIF/storage round-trip tests. |
| REQ-006 | When SARIF is generated, ScorchKit shall use typed locations and stable partial fingerprints and shall not place raw evidence in fingerprint fields. | SARIF structural and secret-leak regression tests. |
| REQ-007 | When existing callers use `Finding::new`, builders, root re-exports, reports, or storage queries, ScorchKit shall preserve their source and wire compatibility except that newly attached secret-bearing evidence is redacted. | Existing tests, facade identity check, and exact DIFF gate. |
| REQ-008 | When TICKET-010 is delivered, ScorchKit shall introduce no new network, filesystem, cloud, credential, or subprocess effect and shall require no full mutation campaign. | Effect review, focused tests, `gate --fast`, and exact-tree `gate --focused-repair`. |

## Scope

- In: versioned finding/observation schema; typed locations; provenance; deterministic identities;
  correlation keys; evidence redaction; labeled agent analysis; compatibility reader; JSON/SARIF
  projection; append-preserving PostgreSQL persistence; Semgrep and Nuclei producer enrichment.
- Out: new scanner execution, automated exploitation, credential acquisition, authentication-flow
  changes, remote target activity, scanner-specific deep integrations, full mutation testing.

## Locked decisions

- Core owns every new domain type; CLI, reports, storage, adapters, and agents consume it.
- `Finding` remains the compatibility facade and legacy fields remain serialized.
- Legacy records are upgraded on deserialization; no destructive migration of report files is
  required.
- Stable identity excludes timestamps, confidence, descriptions, and evidence. Explicit
  correlation keys take precedence; otherwise CWE/rule identity plus canonical typed location is
  used.
- Scanner evidence and agent analysis are different typed collections and cannot overwrite one
  another.
- Secret redaction occurs before evidence enters the finding contract.
- PostgreSQL keeps the latest compatibility snapshot and an append-only, identity-deduplicated
  evidence history.
- Semgrep and Nuclei prove the source and runtime producer paths; other adapters continue through
  the compatibility constructor until enriched later.
- The owner-approved mutation repair scope is the complete 25-survivor set from the completed DIFF
  baseline; the broad inventory remains deferred and no repository-wide rerun is authorized.

## Recon

- Existing code has 382 production `Finding::new` call sites; a compatibility-first core upgrade
  avoids an unsafe repository-wide constructor rewrite.
- The current storage fingerprint includes scanner module and title, so equivalent cross-scanner
  observations cannot correlate; the v2 identity replaces that storage key for new records.
- Current storage overwrites evidence during deduplication; a child evidence table is required to
  retain distinct observations.
- Current SARIF uses evidence as a fingerprint; that leaks content and is not a stable identity.
- `HttpEvidence` currently retains raw headers, URLs, and bodies and lacks route, parameter, and
  persona identity.
- SK-029 already separates provider output from scanner findings; TICKET-010 extends that separation
  into the durable finding schema rather than changing provider execution.

## Notes

- Active pipeline: `docs/planning/pipeline/completed/appsec-evidence-v2.spec.md`

## Log

- 2026-08-19: opened.
- 2026-08-19: implementation, adversarial inspection, exact survivor repair, and focused-repair
  validation completed; ready for pipeline-controlled archival.
