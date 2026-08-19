---
title: Version application-security evidence and finding identity — notes
pipeline_id: 6cea6623-3df1-4a51-96b3-b1c51995acdc
---

# Version application-security evidence and finding identity — running notes

Chronological and append-only. Record decisions, evidence, dead ends, and corrections.

## Phase 1 — Plan

- Recalled knowledge: store invariants must be atomic; provider output is validated at consumption;
  effect contracts have one core source; workspace DIFF scope is exact; facade type identity must be
  preserved; adapter execution descriptors remain provider-neutral; malformed parser output is not
  a clean scan; ticket baseline and green receipt reuse rules apply; focused mutation repair is not
  an ordinary feature-delivery substitute.
- Recon: 382 production `Finding::new` calls make compatibility-first evolution safer than a broad
  constructor migration. Existing SARIF fingerprints contain evidence, existing storage overwrites
  evidence during deduplication, and `HttpEvidence` stores secret-bearing data without redaction.
- Operator confirmation: owner explicitly asked to continue and finish TICKET-010 on 2026-08-19.

## Phase 2 — Design

- Architecture: `Finding` remains the facade and owns a canonical `FindingRecordV2`. Core types
  cover typed locations, provenance, evidence records, correlation keys, deterministic identities,
  and labeled agent analysis. Redaction happens before durable attachment. PostgreSQL upserts the
  stable finding and appends distinct child evidence in one transaction. JSON and SARIF project the
  same record. See `docs/architecture/application-security-evidence.md`.
- File manifest: add `crates/scorchkit-core/src/observation.rs` and migration
  `migrations/009_appsec_evidence_v2.sql`; modify core evidence/finding/lib/manifest, storage model
  and finding CRUD, SARIF, Semgrep, Nuclei, Cargo lock, storage/report/parser tests, architecture
  index/content, and pipeline artifacts. No registry, policy, executor, authentication, or target
  code changes.
- Regression test plan: core legacy upgrade and v2 round trip; source/runtime/package/artifact
  serialization; delimiter-safe stable identity; cross-scanner CWE/correlation convergence;
  evidence identity distinctness; HTTP header/query/body redaction and UTF-8 truncation; Semgrep
  source/rule provenance; Nuclei runtime/template provenance; SARIF typed locations and no evidence
  fingerprints or secret leakage; PostgreSQL cross-scanner upsert plus two evidence children;
  existing focused unit/integration suites; fast gate; exact-tree DIFF gate.
- Design risk review: public legacy fields can be mutated after construction. Identity and report
  projections therefore derive from a normalized clone at consumption boundaries, and explicit
  enrichment builders re-synchronize the canonical record. No design assumes public fields are
  immutable.
- Operator confirmation: owner explicitly asked to finish TICKET-010; the design remains within the
  promoted SK-035 intake and introduces no new effect class.

## Phase 3 — Implement

- Files and behavior changed: added the provider-neutral observation contract in
  `crates/scorchkit-core/src/observation.rs`; upgraded `Finding` and `HttpEvidence` with compatible
  v2 serialization and consumption-time normalization; enriched Semgrep and Nuclei with typed
  location/provenance; added migration 009 and transactional tracked-finding/evidence/analysis
  persistence; projected the same canonical record into SARIF, HTML, PDF, and terminal reports;
  preserved root facade type identity; and added core, adapter, report, architecture, and PostgreSQL
  regressions.
- Identity inputs use fixed-width length prefixes. Explicit correlation keys are hashed as separate
  namespace/value parts, and evidence JSON is canonicalized recursively before hashing so map
  iteration order cannot change identity.
- Design deviations: evidence uniqueness includes `scan_id` in addition to tracked finding and
  evidence identity. This retains a same-evidence observation once per scan while still suppressing
  duplicate writes within one scan. `HttpEvidence` also gained custom serde normalization so direct
  serialization after public-field mutation cannot bypass redaction.
- Focused implementation evidence: `scorchkit-core` 128 tests and 4 doc tests passed; strict
  all-target/all-feature clippy passed; the fresh-schema PostgreSQL cross-scanner regression passed.

## Phase 3.5 — Inspect ledger

| # | Critic | Finding | Severity | Disposition |
|---|---|---|---|---|
| 1 | Integrity | HTTP header maps were serialized directly when deriving evidence identity, so randomized map order could produce different digests for equivalent evidence. | High | Fixed by recursively canonicalizing JSON objects before hashing; added a reversed-header-order regression. |
| 2 | Correctness | `tracked_findings.identity_schema` stored `scorchkit.finding/v2` even though the column describes the stable identity algorithm. | Medium | Fixed migration defaults and all storage writes/tests to use `scorchkit.finding-identity/v1`. |
| 3 | Integrity | Multiple correlation keys were joined with delimiter characters before hashing, allowing crafted namespace/value boundaries to be ambiguous. | Medium | Fixed by hashing every normalized namespace and value as a separate length-prefixed part; added a collision regression. |
| 4 | Simplification | New report string collection and the transactional save routine violated strict quality limits. | Low | Replaced format collection with direct writes and extracted cohesive storage helpers; strict clippy is green without suppressions. |
| 5 | Security | Redaction could be bypassed by mutating public HTTP compatibility fields after construction and serializing them directly. | High | Added custom `HttpEvidence` serde that re-redacts URLs, headers, and keyed bodies; direct-mutation regression is green. |

## Phase 4 — Validate

- Tests run (commands and outcomes): focused core, HTML, Semgrep, Nuclei, SARIF, storage, and
  PostgreSQL regressions passed during repair; `scorchkit-core` has 134 unit tests plus four doc
  tests; formatting and strict workspace all-target/all-feature Clippy passed. The final
  focused-repair gate passed all 19 applicable lanes, including the complete feature matrix, 1,050
  root all-feature tests, 1,494 strict Nextest cases with six reasoned skips, 79.44% line coverage,
  PostgreSQL integration, and CLI/MCP contracts.
- Gate run and receipt: the completed DIFF baseline selected 157 mutations across 72 functions in
  ten files: 84 caught, 25 missed, 48 unviable, and no timeouts. The owner stopped repeat broad
  scans and approved rerunning only the fixed cases. The exact 25-survivor recheck finished with
  24 caught, one deliberate infinite-loop timeout in `floor_char_boundary`, zero misses, and zero
  unviable. The verifier reconstructs 109/109 viable caught and 100% MSI from raw outcomes at
  `.git/scorchkit-mutants-focused-ticket-010`, with evidence digest
  `52b8ccb70199bef3ac6eac4f718d340b7152821ae00d17d8665aac97f4b97eb2`. The green
  focused-repair receipt binds that digest and the exact worktree.
- Documented skips with reasons: gates 17–19 are the repository's named web-only skips because the
  terminal engine has no web UI, website renderer, or CSS asset pipeline. Six Nextest skips are
  reasoned live-network tests and are not used as delivery proof.

## Phase 5 — Complete

- Docs updated: the changelog and application-security evidence, report, and storage architecture
  documents describe the v2 contract, compatibility facade, redaction boundary, stable identity,
  append-preserving persistence, and labeled projections. The ticket/spec record the exact
  owner-approved focused repair scope and keep the broad campaign deferred.
- AAR submitted: `AAR-010-appsec-evidence-v2` records the five inspection failures, the mutation
  repair lesson, five reusable prevention rules, and a 5/5 effectiveness assessment.
- Archive: this notes/spec pair and TICKET-010 are ready for pipeline-controlled archival. The
  archive invalidates the pre-completion receipt, so delivery reruns the same focused-repair gate
  without launching cargo-mutants.

## Defect and lesson ledger

| # | What broke | Root cause | Fix | Prevention |
|---|---|---|---|---|
| 1 | First strict clippy run rejected five new quality violations. | Report rendering accumulated formatted strings and two implementation functions exceeded the repository line limit. | Used direct string writes and extracted Nuclei/storage helpers without changing behavior. | Keep strict clippy in the focused implementation loop before phase transition. |
| 2 | The disposable validation database reported a changed migration checksum during iteration. | Migration 009 had already been applied before inspection corrected its schema label and uniqueness contract. | Recreated only `scorchkit_codex_validation_001` as owner `cpeppers`, then reran the fresh-schema PostgreSQL proof. | Treat pre-delivery migration databases as disposable and always revalidate the final migration from a fresh schema. |
| 3 | An early fast gate reported obsolete ShellCheck and missing Gitleaks/Semgrep versions. | The remote command omitted `/home/cpeppers/.local/bin`, selecting the distribution ShellCheck and hiding owner-installed tools. | Restored the configured user-local path and verified ShellCheck 0.11.0, Gitleaks 8.30.1, and Semgrep 1.156.0. | Preserve the build host's configured tool path in every remote validation command. |
| 4 | The first DIFF gate ended red after every non-mutation lane passed. | The new identity, canonicalization, report, redaction, and advisory-lock branches had 25 surviving mutants; post-mutation load also made one unrelated ownership test exceed its ten-second observation budget. | Added direct ticket-scoped assertions and used the owner-approved focused repair path; the final unloaded Nextest run passed all 1,494 executed cases. | Use the completed broad survivor inventory as the repair ledger and do not treat a post-mutation timing failure as product evidence until an ordinary run confirms it. |
| 5 | Two focused rechecks exposed deduplication and re-redaction assertions that depended on incidental paths. | Round-trip tests observed final normalized state but did not prove the first normalization branch or independent collection deduplication. | Added direct assertions at `canonical_appsec` and `HttpEvidence::redacted`, then proved the exact branch mutants before the final 25-case run. | A mutation repair must assert the changed branch's immediate contract, not only a downstream round trip. |
