---
title: Add an authenticated multi-user deployment profile
pipeline_id: d13e74eb-1bc8-44e0-be40-31a530d09fe6
status: Phase 5 — Complete PASS; ready for delivery
ticket: TICKET-034
ticket_doc: docs/planning/tickets/closed/TICKET-034-team-suite.md
aar: docs/planning/knowledge/aar/AAR-034-team-suite.md
focused_repair: approved
focused_evidence: scorchkit-mutants-focused-ticket-034
created: 2026-08-24
---

# Add an authenticated multi-user deployment profile — spec

## Intent

Ship an optional team-service profile that authenticates trusted-proxy requests into one exact
organization/project cell and role, then reuses the existing control service inside a hard
database, queue, event, encrypted-object, key, quota, audit, and recovery boundary. Preserve local
operation and keep authority in engagement policy rather than client, proxy, role, or UI claims.

## Scope

- In: optional team contract and configuration; loopback trusted-proxy transport; environment-
  indirect credential and key preparation; database-per-cell composition; exact RBAC; quota and
  retention admission; encrypted filesystem object storage; append-only team audit; versioned
  backup manifest verification; adversarial two-cell fixtures; docs and gates.
- Out: direct TLS/public bind, OAuth/OIDC/password/session service, client-selected authority,
  row-shared tenancy, cloud object SDKs, cross-tenant superadmin, in-place destructive restore,
  browser-owned bearer, direct storage access by frontends, or any required team dependency for
  the local profile.
- Focused repair: exactly the 94 completed DIFF survivors in 37 functions across six files; retain
  the 732-mutant raw baseline and recheck those exact names without another broad run.

## Acceptance criteria (EARS)

| ID | EARS Requirement | Verification |
|---|---|---|
| REQ-001 | When the team profile starts, ScorchKit shall validate every listener, authority, binding, cell, engagement, database identity, object root, key ring, quota, and retention invariant before listening. | Configuration boundary tests and real startup preflight. |
| REQ-002 | When a bearer is accepted, ScorchKit shall derive the exact cell, principal, role, and engagement only from its constant-time credential binding and shall remove the authorization header before routing. | Authentication/spoofing/header-retention tests. |
| REQ-003 | When a control operation is requested, ScorchKit shall enforce a complete role matrix before dispatch and the existing service shall independently enforce request, policy, and canonical-storage invariants. | Exhaustive operation matrix and denial-before-effect tests. |
| REQ-004 | When separate cells execute concurrently, ScorchKit shall keep database rows, jobs, webhook deliveries, event cursors, object bytes, keys, quotas, retention, and audits isolated even under wrong identifiers and corrupt context. | Two-cell concurrency/corruption integration matrix. |
| REQ-005 | When a team object is written or read, ScorchKit shall require the exact local-state grant, use authenticated cell-key encryption, enforce immutable digest metadata and hard budgets, and fail closed on tampering, symlinks, key drift, or expiry. | Object-store unit/property and filesystem adversarial tests. |
| REQ-006 | When a team operation reaches a terminal outcome, ScorchKit shall append a credential-safe immutable audit event with exact cell, principal, role, request, action, outcome, and timestamp attribution. | Audit parity, redaction, trigger, and sequencing tests. |
| REQ-007 | When a cell backup is verified or restored, ScorchKit shall validate the versioned manifest and every database/object digest both before and after consumption and shall require a distinct destination identity. | Local PostgreSQL backup/corruption/restore rehearsal. |
| REQ-008 | When team support is absent or disabled, ScorchKit shall preserve all local defaults and host contracts without a team service, credential, database cell, key, object root, or remote queue. | Feature/default/workspace compatibility suite. |

## Locked decisions

| # | Decision | Why |
|---|---|---|
| 1 | Use separate deployment cells, each with a distinct PostgreSQL database, object root, key ring, service, queues, journal, quotas, and audit trail. | Isolation remains true for every existing/future storage query and wrong-cell resource identifier without pervasive row predicates. |
| 2 | Bind each credential to one cell, role, subject, and engagement before parsing tenant claims or routing. | Authority cannot be selected by request metadata, resource identifiers, sessions, or a frontend. |
| 3 | Keep the backend loopback-only behind a trusted same-host TLS proxy. | Existing remote-boundary hardening applies and ScorchKit does not acquire direct TLS/public-listener complexity. |
| 4 | Apply RBAC as a narrowing pre-dispatch layer and preserve existing control-policy validation. | Team membership cannot grant an unscoped target, capability, effect, or canonical mutation. |
| 5 | Store only authenticated ciphertext in cell-specific object roots and require an exact local-state policy grant. | Remote artifacts gain confidentiality/integrity without exposing a storage credential or bypassing filesystem authorization. |
| 6 | Verify recovery into a distinct destination using a versioned digest manifest. | Failure and corruption cannot overwrite the active cell or silently change canonical identities. |
| 7 | Make all team configuration optional and feature-scoped. | Local CLI, MCP, API, console, storage, and execution remain complete and unchanged. |
| 8 | Preserve the completed DIFF baseline and rerun only its exact 94-survivor repair set. | The owner directed continuation of the mutation cleanup without repeating broad mutation work. |

## Linked artifacts

- Ticket: `docs/planning/tickets/closed/TICKET-034-team-suite.md`
- AAR: `docs/planning/knowledge/aar/AAR-034-team-suite.md`
- Architecture: `docs/architecture/team-service.md`

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
