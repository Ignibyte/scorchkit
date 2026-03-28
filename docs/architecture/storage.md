# Storage Architecture

**Date:** 2026-03-28
**Pipeline:** WORK-PostgreSQL-Storage-Layer (#1)

## Decision

PostgreSQL via `sqlx` (async, runtime queries with `FromRow` derives) behind a `storage` Cargo feature flag.

## Rationale

- **PostgreSQL over SQLite**: concurrent access from MCP server + CLI, JSONB columns for flexible finding storage, full-text search, production-grade
- **Runtime queries over compile-time macros**: `sqlx::query_as!()` requires `DATABASE_URL` at build time which breaks CI and binary distribution; runtime `sqlx::query_as()` with `FromRow` trades compile-time SQL verification for build portability
- **Feature flag**: `--features storage` opt-in keeps default CLI build lightweight (no libpq dependency)

## Schema

```
projects (id, name, description, settings JSONB, created_at, updated_at)
    └── project_targets (id, project_id FK, url UNIQUE(project_id,url), label)
    └── scan_records (id, project_id FK, target_url, profile, started_at, completed_at, modules_run TEXT[], modules_skipped TEXT[], summary JSONB)
        └── tracked_findings (id, scan_id FK, project_id FK, fingerprint, module_id, severity, title, description, affected_target, evidence, remediation, owasp_category, cwe_id, raw_finding JSONB, first_seen, last_seen, seen_count, status)
```

## Finding Deduplication

Fingerprint = SHA-256(module_id | title | affected_target). Deliberately excludes evidence and timestamp so the same vulnerability found on different scans maps to the same tracked finding. `affected_target` is included so XSS on `/login` and XSS on `/register` track separately.

## Vulnerability Lifecycle

```
New → Acknowledged → Remediated → Verified
       ↘ FalsePositive
```

## Module Structure

```
src/storage/
  mod.rs        — connect(), connect_with_max()
  models.rs     — Project, ProjectTarget, ScanRecord, TrackedFinding, VulnStatus
  projects.rs   — CRUD + target management
  scans.rs      — save/get/list scan records
  findings.rs   — save with dedup, status lifecycle, query by severity/status/scan
  migrate.rs    — run embedded migrations
migrations/
  001_initial.sql
```

## Alternatives Considered

| Alternative | Rejected Because |
|-------------|-----------------|
| SQLite | No concurrent access, no JSONB, not production-grade for team deployments |
| sqlx compile-time macros | Requires DATABASE_URL at build time, breaks CI/distribution |
| Diesel ORM | Heavier abstraction, code generation, less control over queries |
| SeaORM | Additional abstraction layer not needed for straightforward CRUD |
