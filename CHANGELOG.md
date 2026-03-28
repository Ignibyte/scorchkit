# Changelog

All notable changes to ScorchKit will be documented in this file.

## [0.3.0] - 2026-03-28

### Added
- **Project model CLI commands** — `scorchkit project create/list/show/delete` for managing security assessment projects
- **Target management** — `scorchkit project target add/remove/list` for managing project targets
- **Finding management** — `scorchkit finding list/show/status` for querying and updating vulnerability lifecycle
- **Database migration command** — `scorchkit db migrate` for schema initialization
- **Scan persistence** — `scorchkit run <url> --project <name>` persists scan records and findings to PostgreSQL
- **Database URL resolution** — `--database-url` CLI flag > `config.toml` > `DATABASE_URL` env var precedence
- **`connect_from_config()`** — shared DB connection helper with auto-migration support
- **`get_project_by_name()`** — lookup projects by name (users never need to type UUIDs)
- **`list_findings()`** — unfiltered project finding query
- All new commands feature-gated behind `storage` Cargo feature — default build unaffected

## [0.2.0] - 2026-03-28

### Added
- **PostgreSQL storage layer** (`src/storage/`) — persistent project, scan, and finding storage via `sqlx`
- **Project model** — create, list, get, update, delete projects with associated targets
- **Scan records** — store scan execution history linked to projects
- **Finding deduplication** — SHA-256 fingerprint (module_id + title + affected_target) deduplicates findings across scans
- **Vulnerability lifecycle tracking** — `VulnStatus` enum: New → Acknowledged → FalsePositive → Remediated → Verified
- **`storage` Cargo feature flag** — opt-in PostgreSQL support, default CLI build unaffected
- **`DatabaseConfig`** in `AppConfig` — configurable connection URL, pool size, auto-migration
- **Database migration** (`migrations/001_initial.sql`) — projects, project_targets, scan_records, tracked_findings tables with indexes
- **`Database` error variant** in `ScorchError` — clean error propagation from storage layer
- Pipeline enforcement system — CONSTITUTION.md, 8 hooks, 12 slash commands, pipeline templates
- `.semgrep.yml` — 8 Rust security rules
- `deny.toml` — license compliance and dependency advisory configuration
- `rustfmt.toml` — code formatting configuration

## [0.1.0] - 2026-03-25

### Added
- Initial release: 41 scan modules (20 built-in + 21 external tool wrappers)
- Claude AI integration for finding analysis
- 4 output formats: terminal, JSON, HTML, SARIF
- Scan diffing, profiles, proxy support, authenticated scanning
