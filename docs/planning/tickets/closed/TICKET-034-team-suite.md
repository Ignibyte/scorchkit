---
title: TICKET-034-team-suite
status: done
ticket_number: 034
type: feature
created: 2026-08-24
closed: 2026-08-26
intake: docs/planning/intake/INTAKE-team-suite.md
pipeline_spec: docs/planning/pipeline/completed/team-suite.spec.md
focused_repair: approved
focused_evidence: scorchkit-mutants-focused-ticket-034
---

# Add an authenticated multi-user deployment profile

## Summary

Add an optional authenticated team-service profile that routes each trusted-proxy bearer to one
preconfigured organization/project cell, role, and engagement. Every cell owns a distinct
PostgreSQL database, durable job and webhook queues, event journal, encrypted content-addressed
object root and key ring, quotas, retention policy, append-only service audit, and verifiable
backup/restore manifest. The existing local CLI, MCP, control API, and console remain complete.

## Why

SK-044 established remote transport identity, SK-048 established upgrade/restore integrity,
SK-049 established the application-service API, and SK-055 proved the optional console boundary.
The next safe step is multi-user routing with isolation and recovery enforced before a frontend or
reverse proxy can present project membership as authority.

## EARS Requirements

| ID | EARS Requirement | Verification |
|---|---|---|
| REQ-001 | When the team profile starts, ScorchKit shall validate a loopback trusted-proxy backend, exact public authorities, unique credential-indirect bindings, enabled unexpired engagements, one role and one cell per credential, distinct database identities and object roots, bounded quotas, and a complete encryption key ring before listening. | Startup matrix, duplicate/collision tests, real PostgreSQL identity checks, root/symlink negatives, and absent-secret tests. |
| REQ-002 | When a team request is authenticated, ScorchKit shall select its organization, project, role, database, queue, object root, key context, engagement, and event journal only from the constant-time credential binding and shall ignore or reject client tenant, role, subject, and engagement claims. | Spoofing, wrong-cell identifier, header-removal, anti-enumeration, and cross-cell concurrent tests. |
| REQ-003 | When a role invokes the team control API, ScorchKit shall enforce an exact reader, analyst, operator, or administrator operation matrix before the existing control service revalidates engagement policy, canonical identity, and command inputs. | Exhaustive role/operation matrix and denial-before-dispatch assertions. |
| REQ-004 | When work is queued or recovered in a team cell, ScorchKit shall enforce cell rate, active-job, subscriber, event, and storage budgets without widening the bound engagement or consuming another cell's capacity. | Exact quota edges, fairness, cancellation/recovery, and exhaustion-isolation tests. |
| REQ-005 | When evidence, reports, or extension artifacts enter team object storage, ScorchKit shall authorize the configured local-state root, encrypt bytes with the cell write key, bind ciphertext to immutable metadata, enforce digest/size/count/retention limits, audit the result, and never return keys or plaintext diagnostics. | Encryption round-trip/tamper, key rotation, path-race/symlink, quota, expiry, redaction, and audit tests. |
| REQ-006 | When a team request succeeds, fails, or is denied, ScorchKit shall append a bounded credential-safe audit event in the selected cell and shall reject mutation or deletion of the durable audit history. | Success/denial/error parity, secret search, PostgreSQL append-only trigger, and concurrent sequence tests. |
| REQ-007 | When backup or recovery is rehearsed, ScorchKit shall verify a versioned manifest over the database snapshot, encrypted object inventory, cell identity, key identifiers, migrations, and canonical identity probes before restoring into a distinct destination and shall reverify it after consumption. | Disposable two-cell backup/corruption/restore/upgrade matrix using local PostgreSQL and object fixtures. |
| REQ-008 | When the team feature or profile is disabled, ScorchKit shall retain byte-for-byte-compatible local configuration defaults and complete local CLI, MCP, control API, console, storage, and execution behavior without team identity, object storage, or queue configuration. | Default-config, feature matrix, workspace direction, headless contracts, and existing gate lanes. |

## Scope

- In: optional team contract/configuration; trusted-proxy loopback team API; credential-to-cell
  routing; four-role RBAC; one database/queue/journal/object/key/quota/audit boundary per cell;
  encrypted filesystem object backend; backup manifest verifier; two-cell PostgreSQL tests;
  documentation and delivery wiring.
- Out: direct TLS; public backend binds; OAuth/OIDC or password/session ownership; client-selected
  tenants, projects, roles, subjects, engagements, database URLs, roots, or key IDs; shared rows or
  object prefixes between cells; cloud object-store SDKs; cross-organization administration;
  anonymous access; direct frontend database writes; weakening local operation.

## Locked decisions

- A deployment cell is the hard organization/project isolation unit. Separate databases, roots,
  key rings, queues, journals, and service instances are required; row-level filters are not the
  primary tenant boundary.
- The trusted same-host proxy owns TLS and connection/header budgets. The ScorchKit backend remains
  loopback-only and authenticates each request independently with an environment-backed bearer.
- Every bearer binds to exactly one cell, one role, and one engagement. A principal using multiple
  cells receives distinct credentials, so request data never selects authority.
- RBAC narrows access before the existing control service; it never replaces engagement policy or
  canonical storage validation.
- Team object writes additionally require the bound engagement's exact local-state grant for the
  configured canonical root. Ciphertext is cell-keyed and content metadata is authenticated.
- Backups are restored only into a distinct destination after pre-consumption verification; an
  in-place destructive restore is outside this ticket.
- The owner approved repair and exact-name recheck of all and only the completed DIFF's 94
  survivors in 37 functions across six files. The completed 732-mutant raw baseline remains
  preserved; another broad mutation run is explicitly out of scope.

## Recon

- Existing remote MCP already proves pre-routing authentication and principal-specific session
  ownership but is intentionally single-engagement and has no tenant/RBAC selection.
- The control service is the only application command/query boundary and already rechecks the
  bound engagement on each request. Its current HTTP adapter is loopback-only and single-principal.
- Jobs and webhook deliveries are durable PostgreSQL queues; journal state is process-local and
  bounded. A cell-specific service instance keeps all three isolated without adding tenant columns
  to every canonical record.
- Current PostgreSQL tables are not tenant-keyed, and several job/finding operations identify
  resources indirectly. Retrofitting row filters would make isolation depend on every present and
  future query; distinct cell databases make wrong-cell identifiers uniformly absent instead.
- The release qualification test already verifies a digest before and after `pg_restore` into a
  separate database. Team recovery extends that invariant across cell identity and encrypted
  objects rather than inventing in-place recovery.

## Notes

- Active pipeline: `docs/planning/pipeline/completed/team-suite.spec.md`
- Operator direction at plan was to continue through the roadmap, commit locally without pushing,
  and avoid repeated broad mutation campaigns. On 2026-08-26 the owner replaced the remote,
  selected `git@github.com:Ignibyte/scorchkit.git`, and authorized proceeding with delivery to its
  `main`; exact survivor handling remains required.

## Log

- 2026-08-24: opened.
- 2026-08-24: promoted from `INTAKE-team-suite`; selected database-per-cell isolation so tenant
  safety does not depend on retrofitting every canonical query with a row predicate.
- 2026-08-26: recorded the owner's direction to continue the mutation cleanup as approval for an
  exact focused repair of the completed DIFF's 94 survivors, with the raw 732-mutant baseline
  preserved under `.git/scorchkit-mutants-focused-ticket-034/initial`.
- 2026-08-26: sealed the canonical focused evidence after a 94/94 exact-name recheck; the verifier
  reconstructed 656/656 viable outcomes caught at 100% MSI with zero final survivors.
- 2026-08-26: preserved the one-file post-seal Clippy transition and completed its exact 26-mutant,
  nine-function follow-up at 100% MSI; the resealed focused evidence verifies the current tree.
- 2026-08-26: passed the exact 22-lane focused-repair validation gate with zero failures or skips,
  85.85% line coverage, 2,246 nextest cases, 105 PostgreSQL cases, 116 CLI/MCP contracts, both
  browser surfaces, and sealed 656/656 viable mutation outcomes caught.
