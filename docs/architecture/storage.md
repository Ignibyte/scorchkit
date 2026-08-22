# Storage Architecture

**Date:** 2026-03-28
**Pipeline:** WORK-PostgreSQL-Storage-Layer (#1)

## Decision

PostgreSQL via `sqlx` (async, runtime queries with `FromRow` derives) behind a `storage` Cargo feature flag.

## Rationale

- **PostgreSQL over SQLite**: concurrent access from MCP server + CLI, JSONB columns for flexible finding storage, full-text search, production-grade
- **Runtime queries over compile-time macros**: `sqlx::query_as!()` requires `DATABASE_URL` at build time which breaks CI and binary distribution; runtime `sqlx::query_as()` with `FromRow` trades compile-time SQL verification for build portability
- **Feature flag**: `--features storage` opt-in keeps default CLI build lightweight (no libpq dependency)
- **Exact driver graph**: production, model-package, and test SQLx declarations disable defaults
  and enable only PostgreSQL plus the runtime, TLS, data, derive, macro, and migration capabilities
  each owner uses. MySQL, SQLite, and `any` drivers are inactive; optional driver metadata in the
  Cargo lockfile does not activate those code paths.
- **Local peer identity**: the shared connection adapter preserves PostgreSQL's operating-system
  username default for `postgresql:///database` URLs, while explicit authority or query usernames
  win. Invalid URL and driver-option diagnostics do not echo credential-bearing input.

## Schema

```
projects (id, name, description, settings JSONB, created_at, updated_at)
    └── project_targets (id, project_id FK, url UNIQUE(project_id,url), label)
    └── scan_records (id, project_id FK, target_url, profile, started_at, completed_at, modules_run TEXT[], modules_skipped TEXT[], summary JSONB, execution_evidence JSONB)
        └── tracked_findings (id, scan_id FK, project_id FK, stable_identity, identity_schema, correlation_keys JSONB, compatibility fields, raw_finding JSONB, lifecycle fields)
            ├── finding_evidence (scan_id FK, evidence_identity, evidence_schema, raw_evidence JSONB, collected_at)
            └── finding_agent_analysis (analysis_identity, analysis_schema, raw_analysis JSONB, created_at)
    └── attack_paths (path_identity, schemas, current_state, raw_path JSONB, timestamps)
        └── attack_path_transitions (transition_identity, schema, raw_transition JSONB, observed_at)

scan_jobs (id, root_job_id, parent_job_id, attempt, state, revision, owner_id, lease_expires_at, document JSONB, timestamps)
    └── scan_job_audit_events (job_id, revision, state, occurred_at, event JSONB)
```

## Finding identity and evidence preservation

The canonical `scorchkit.finding/v2` identity uses a standards/correlation/rule weakness key plus a
typed location. Evidence, descriptions, confidence, timestamps, and agent interpretation are
excluded. Equivalent cross-scanner observations can therefore converge without using raw evidence
as identity, while different locations remain separate. The old fingerprint remains only to migrate
existing rows on first observation.

Finding upsert, evidence insertion, and labeled analysis insertion share a transaction guarded by a
project/finding advisory lock. Scanner evidence is unique per finding, scan, and evidence identity:
repeat saves within one scan deduplicate, while later scans and different evidence remain available.
Agent analysis has its own child table and cannot overwrite or masquerade as scanner evidence. See
`docs/architecture/application-security-evidence.md`.

`scan_records.execution_evidence` stores the stable `scorchkit.scan-execution-evidence.v1`
projection: exact execution status, typed module outcomes, and the optional canonical application
supply-chain assessment. Legacy callers continue to write an empty object; production scan callers
use the evidence-aware save path so missing or degraded analyzer coverage remains durable beside the
summary.

Canonical attack paths use a separate project/path advisory lock. A snapshot update must contain
every already-stored transition with identical content; stale or conflicting history is rejected.
The child table is authoritative on reads, so updating `raw_path` cannot erase verification proof.
Stored path, selector, attempt, and transition identities are revalidated before use. Project
deletion cascades through both path tables. See
`docs/architecture/source-runtime-correlation.md`.

## Vulnerability Lifecycle

```
New → Acknowledged → Remediated → Verified
       ↘ FalsePositive
```

## Module Structure

```
crates/scorchkit-storage/src/lib.rs
                — Project, ProjectTarget, ScanRecord, TrackedFinding, VulnStatus
src/storage/
  mod.rs        — connect(), connect_with_max()
  models.rs     — compatibility re-exports
  projects.rs   — CRUD + target management
  scans.rs      — save/get/list scan records
  findings.rs   — stable-identity upsert, batched append-preserved evidence/analysis, lifecycle queries
  attack_paths.rs — identity-locked snapshots and append-only transition history
  jobs.rs       — provider-neutral job store adapter with transactional revision audit
  migrate.rs    — run embedded migrations
migrations/
  001_initial.sql … 011_attack_paths.sql
```

Scan job domain types, `JobStore`, and the in-memory store live in `scorchkit-executor::job`. The
root `runner::job` module owns the composed scan service, and `src/storage/jobs.rs` owns the
PostgreSQL adapter. The
database adapter duplicates only indexed lifecycle fields beside the JSONB domain document. Every
successful create or compare-and-swap writes its compact append-only audit event in the same
transaction. See `docs/architecture/jobs.md`.

## Alternatives Considered

| Alternative | Rejected Because |
|-------------|-----------------|
| SQLite | No concurrent access, no JSONB, not production-grade for team deployments |
| sqlx compile-time macros | Requires DATABASE_URL at build time, breaks CI/distribution |
| Diesel ORM | Heavier abstraction, code generation, less control over queries |
| SeaORM | Additional abstraction layer not needed for straightforward CRUD |
