---
title: Add a signed extension catalog and lifecycle
pipeline_id: b04dd984-1a3f-4ee7-b4be-529055060e37
status: Phase 5 — Complete PASS; ready for delivery
ticket: TICKET-035
ticket_doc: docs/planning/tickets/closed/TICKET-035-extension-catalog.md
aar: docs/planning/knowledge/aar/AAR-035-extension-catalog.md
focused_repair: approved
focused_evidence: scorchkit-mutants-focused-ticket-035
created: 2026-08-26
---

# Add a signed extension catalog and lifecycle — spec

## Intent

Ship a local-first signed catalog and explicit lifecycle for the existing isolated WebAssembly
extensions. Verify exact publisher, payload, manifest, module, compatibility, provenance, and
conformance identities before approval; make permission widening reviewable; pin activation and
rollback; block revoked releases before worker startup; preserve historical provenance; and retain
complete built-in and exact locally approved operation when catalogs are offline.

## Scope

- In: provider-neutral catalog/lifecycle contracts; Ed25519 local trust configuration; bounded
  local signed catalog and artifact verification; normalized permission diff; explicit approvals;
  atomic activation/rollback registry; revocation; offline exact-release loading; lifecycle events
  and CLI surfaces; documentation and full validation.
- Out: public/remote catalog transport, ambient fetch/discovery, silent update, trust-on-first-use,
  catalog-controlled trust roots, native executable packages, payment/licensing, new broker effects,
  or non-application-security default selection.

## Acceptance criteria (EARS)

| ID | EARS Requirement | Verification |
|---|---|---|
| REQ-001 | When catalog metadata or an extension artifact is accepted, ScorchKit shall verify its Ed25519 signature, exact publisher/key binding, payload and artifact digests, provenance, engine compatibility interval, and passing conformance record before it can enter the approval registry. | Canonical payload/signature, tamper, wrong-publisher/key, digest, compatibility, conformance, and Wasm structural/health tests. |
| REQ-002 | When an install or upgrade adds or widens a capability, strongest effect, target kind, endpoint allowance, credential/filesystem/subprocess request, or resource budget, ScorchKit shall return the exact normalized permission difference and require an explicit matching approval before activation. | Complete permission-lattice/diff truth table and preview/approval mismatch tests. |
| REQ-003 | When an extension release is activated or invoked, ScorchKit shall bind the catalog, publisher, manifest, module, compatibility, conformance, and permission identities to one exact immutable release and shall reject moving or changed inputs. | Activation/restart/reopen-race, invocation provenance, duplicate identity, and changed-file tests. |
| REQ-004 | When a trusted catalog revokes a release or publisher key, ScorchKit shall block new activation and invocation before worker selection, preserve historical findings and lifecycle records, expose a bounded reason, and require a separate reviewed replacement approval. | Revoked active/rollback/key, denial-order, historical projection, and replacement tests. |
| REQ-005 | When activation fails compatibility, conformance, structural startup, health, or durable publication, ScorchKit shall leave the previous approved release active; when rollback is explicitly requested, it shall reactivate only an exact still-approved non-revoked release without changing prior evidence identity. | Failure injection, atomic state, explicit rollback, unavailable/corrupt prior release, and provenance continuity tests. |
| REQ-006 | When a catalog is absent or unavailable, ScorchKit shall continue to invoke exact locally approved releases whose retained inputs still match, shall keep built-in application-security modules available, and shall never fetch from an undeclared source. | Offline restart/invocation, missing catalog, built-in parity, and network/subprocess denial tests. |

## Locked decisions

| # | Decision | Why |
|---|---|---|
| 1 | Catalog v1 accepts only exact configured regular local files and has no URL or fetch field. | Offline and unavailable behavior cannot become implicit network authority. |
| 2 | Verify Ed25519 over domain-separated raw payload bytes and bind a locally configured key ID to one publisher. | Raw bytes avoid JSON canonicalization ambiguity; signed metadata cannot enroll its own trust root. |
| 3 | Sign a bounded payload whose release entries bind manifest bytes/digest, adjacent module digest, provenance, conformance, permission fingerprint, sequence, and validity interval. | One verified subject graph owns every acceptance claim and resists substitution or replay. |
| 4 | Store immutable approved release records plus append-preserved transitions in an exact local lifecycle root; atomically replace only the active pointer after all checks. | Failed activation and rollback cannot erase the last working approval or history. |
| 5 | Normalize permissions into one closed lattice spanning adapter claims, capabilities, effect allowances, and all budgets; approval binds the exact candidate and diff digest. | A UI label or version number cannot hide a widened effect or resource request. |
| 6 | Check release/key revocation before module registration and again before each invocation. | A long-lived process cannot continue executing a release revoked after startup. |
| 7 | Route catalog releases through the unchanged `LoadedExtension`, worker, policy broker, output validation, and global module-ID claim. | Catalog trust is context, not an effect grant or alternate persistence/execution path. |
| 8 | Extend extension provenance and lifecycle projections append-only; never rewrite prior finding/evidence identities during upgrade, rollback, or revocation. | Historical results remain attributable to the bytes that produced them. |
| 9 | Preserve the one completed 399-mutant DIFF inventory, repair all and only its 101 exact survivors in 33 functions across five files, and use the sealed focused-repair path for validation and delivery. | Implements the owner's mutation-cleanup direction without repeating the four-hour broad campaign. |

## Linked artifacts

- Ticket: `docs/planning/tickets/closed/TICKET-035-extension-catalog.md`
- AAR: `docs/planning/knowledge/aar/AAR-035-extension-catalog.md`
- Architecture: `docs/architecture/extensions.md`

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
