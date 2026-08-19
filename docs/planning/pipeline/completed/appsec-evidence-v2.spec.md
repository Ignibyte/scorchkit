---
title: Version application-security evidence and finding identity
pipeline_id: 6cea6623-3df1-4a51-96b3-b1c51995acdc
status: Phase 5 — Complete PASS; ready for delivery
ticket: TICKET-010
ticket_doc: docs/planning/tickets/closed/TICKET-010-appsec-evidence-v2.md
aar: docs/planning/knowledge/aar/AAR-010-appsec-evidence-v2.md
focused_repair: approved
focused_evidence: scorchkit-mutants-focused-ticket-010
created: 2026-08-19
---

# Version application-security evidence and finding identity — spec

## Intent

Make application-security observations durable and correlatable across SAST, DAST, storage,
reports, and trusted agent analysis. The shipped contract is vendor-neutral and versioned while
retaining the public `Finding` facade used by existing scanners.

## Scope

- In: core v2 contracts and compatibility migration; real redaction; stable finding/evidence
  identities; storage migration and append-preserving persistence; typed JSON/SARIF projections;
  Semgrep and Nuclei enrichment; focused unit and PostgreSQL regression tests.
- Out: new effects, new remote scanning, authentication changes, exploit automation, scanner-depth
  expansion, unrelated report redesign, full mutation campaign.

## Acceptance criteria (EARS)

| ID | EARS Requirement | Verification |
|---|---|---|
| REQ-001 | When a finding is constructed or legacy finding JSON is read, ScorchKit shall expose a `scorchkit.finding/v2` record with a typed source, runtime, package, artifact, or legacy location without removing legacy fields. | `scorchkit-core` constructor/migration/round-trip tests. |
| REQ-002 | When scanner evidence is attached, ScorchKit shall retain scanner/version/rule-or-template/config/target-revision/collection-time provenance and assign a deterministic evidence identity. | Core identity tests and Semgrep/Nuclei parser tests. |
| REQ-003 | When HTTP evidence contains sensitive headers, query values, or keyed body values, ScorchKit shall redact them while retaining method, route, parameter identity, authentication persona identity, response status, and truncation state. | Core HTTP redaction tests. |
| REQ-004 | When equivalent observations arrive from different scanners, ScorchKit shall produce the same stable finding identity while retaining distinct raw evidence records. | Core cross-scanner identity test; PostgreSQL child-evidence test. |
| REQ-005 | When agent analysis is attached, ScorchKit shall label and serialize it separately from immutable scanner evidence in JSON, SARIF, and stored finding records. | Core serde, SARIF, and PostgreSQL tests. |
| REQ-006 | When SARIF is generated, ScorchKit shall use typed locations and stable partial fingerprints and shall not place raw evidence in fingerprint fields. | SARIF unit tests. |
| REQ-007 | When existing callers use `Finding::new`, builders, root re-exports, reports, or storage queries, ScorchKit shall preserve their source and wire compatibility except that newly attached secret-bearing evidence is redacted. | Existing suites, facade check, DIFF gate. |
| REQ-008 | When TICKET-010 is delivered, ScorchKit shall introduce no new network, filesystem, cloud, credential, or subprocess effect and shall require no full mutation campaign. | Inspection ledger, fast gate, and focused-repair gate. |

## Locked decisions

| # | Decision | Why |
|---|---|---|
| 1 | Add a canonical v2 companion to the existing `Finding` facade. | Hundreds of adapters keep compiling while every newly constructed and deserialized finding gains the contract. |
| 2 | Infer conservative typed locations and keep a `legacy` location variant. | Migration is lossless and never invents source/runtime precision. |
| 3 | Length-prefix all identity inputs before SHA-256. | Prevent delimiter ambiguity and keep identities deterministic. |
| 4 | Prefer sorted explicit correlation keys; otherwise use CWE or rule identity plus canonical location. | Supports cross-scanner equivalence without collapsing unrelated vulnerabilities. |
| 5 | Redact at evidence construction and re-normalize on finding attachment/deserialization. | Raw secrets do not become durable domain data. |
| 6 | Append evidence in a child table keyed by evidence identity inside the same transaction as tracked-finding upsert. | Deduplication cannot discard distinct observations or leave partial state. |
| 7 | Keep agent analysis in a separate typed collection referenced by finding identity/evidence IDs. | Agent claims remain attributable and cannot masquerade as scanner evidence. |
| 8 | Enrich Semgrep and Nuclei only in this ticket. | Proves SAST and DAST paths while bounding change size. |
| 9 | Preserve the completed DIFF baseline and rerun only its exact repaired survivor set under the focused-repair verifier. | The owner explicitly stopped repeat broad mutation scans and directed reruns only for fixed scope. |

## Owner-approved focused delivery scope

The repository owner stopped repeat broad mutation scans and directed ScorchKit to rerun only the
mutations repaired in this ticket, with a broad campaign deferred until later. The completed DIFF
baseline selected 157 mutations in 72 functions across ten files: 84 were caught, 25 survived, and
48 were unviable. The exact repair scope is all 25 survivors in 11 functions across five files.
The sealed recheck records 24 caught and one timeout (the deliberate infinite-loop mutation in
`floor_char_boundary`), with zero misses or unviable cases. Repository arithmetic therefore closes
all 109 viable baseline mutations at 100% MSI. Raw outcomes and the test-only input transition are
sealed under `.git/scorchkit-mutants-focused-ticket-010`; the broad inventory remains deferred.

## Linked artifacts

- Ticket: `docs/planning/tickets/closed/TICKET-010-appsec-evidence-v2.md`
- AAR: `docs/planning/knowledge/aar/AAR-010-appsec-evidence-v2.md`
- Architecture: `docs/architecture/application-security-evidence.md`

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

## Confirmed design

### Contract and compatibility

- `scorchkit-core` owns `FindingRecordV2`, typed observation locations, scanner provenance,
  evidence records, correlation keys, stable identities, and agent-analysis records.
- The existing `Finding` remains the public facade. Construction and deserialization populate the
  v2 companion while legacy fields and root re-exports remain available.
- Consumption boundaries call `canonical_appsec` so direct mutation of public compatibility fields
  cannot leave stale location, provenance, evidence, analysis, or identity data.

### Identity, redaction, and evidence

- SHA-256 identity inputs use fixed-width length prefixes. JSON objects are recursively
  canonicalized, correlation namespace/value pairs remain separate, and timestamps, descriptions,
  confidence, and evidence are excluded from finding identity.
- HTTP URL queries, sensitive headers, and keyed bodies are redacted at construction and again at
  serialization/attachment boundaries. UTF-8 response truncation retains a valid byte boundary.
- Scanner evidence and agent interpretation use distinct schemas and identity namespaces; report
  projections label analysis and never place evidence content in SARIF fingerprints.

### Producers and persistence

- Semgrep supplies source location plus rule/version/config provenance. Nuclei supplies runtime
  route/parameter/persona evidence plus template/version/config provenance.
- Migration 009 stores the current compatibility snapshot and appends identity-deduplicated
  scanner evidence and agent analysis in the same transaction as the tracked-finding upsert.
  A PostgreSQL advisory transaction lock serializes equivalent identities.

## Phase 3.5 — Inspect ledger

| # | Critic | Finding | Severity | Disposition |
|---|---|---|---|---|
| 1 | Integrity | HTTP header maps entered evidence identity in randomized iteration order. | High | Recursively canonicalized JSON and added reversed-header-order identity coverage. |
| 2 | Correctness | Storage labeled the finding identity column with the record schema rather than the identity algorithm. | Medium | Standardized on `scorchkit.finding-identity/v1` in migration, writes, and tests. |
| 3 | Integrity | Delimiter-joined correlation keys allowed crafted namespace/value boundary ambiguity. | Medium | Hash each sorted namespace and value as a separate length-prefixed identity part. |
| 4 | Simplification | Report collection and transactional storage exceeded strict complexity/line limits. | Low | Extracted cohesive helpers and direct writes; strict linting passes without suppression. |
| 5 | Security | Public HTTP compatibility fields could be mutated after construction and serialized without redaction. | High | Added custom serde normalization and direct mutation tests for URL, headers, and bodies. |

## Phase 4 — Validate

- All 19 applicable focused-repair lanes pass on the build host using NVMe target and temporary
  storage. Evidence includes 1,050 root all-feature tests, 1,494 strict Nextest cases, 79.44% line
  coverage, PostgreSQL integration, and CLI/MCP contracts.
- The preserved DIFF baseline contains 157 mutations: 84 caught, 25 missed, and 48 unviable. The
  exact 25-survivor repair run records 24 caught, one timeout, zero misses, and zero unviable. The
  sealed verifier reconstructs 109/109 viable caught and 100% MSI.
- Gates 17–19 are named web-only skips. Six live-network Nextest cases remain reasoned skips and are
  not delivery evidence.

## Phase 5 — Complete

- Architecture, storage/report guidance, changelog, ticket, running notes, knowledge register, and
  AAR describe the delivered contract and its validation boundary.
- `AAR-010-appsec-evidence-v2` is submitted at 5/5 effectiveness.
- Pipeline completion archives the open ticket and active pair; delivery then reruns the same
  focused-repair gate on the archived exact tree.
