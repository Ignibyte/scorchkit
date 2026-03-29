# Changelog

All notable changes to ScorchKit will be documented in this file.

## [0.11.0] - 2026-03-29

### Changed
- **Expanded all 20 MCP tool descriptions** — upgraded from terse one-liners to 2-4 sentence guidance blocks with when-to-use, key parameters, output format, and next-step recommendations
- **Expanded all parameter descriptions in `types.rs`** — `///` doc comments on `JsonSchema` fields now include valid values, examples, and decision guidance (schemars converts these to JSON Schema `description` fields)
- Claude now receives richer context for each tool call: what the tool does, when to choose it over alternatives, which parameters matter, and what to do with the results

## [0.10.0] - 2026-03-29

### Added
- **Rich MCP system instructions** — comprehensive pentest methodology delivered to Claude on connection
- **7-step engagement workflow** — PTES-adapted: project setup, recon, AI planning, targeted scan, analysis, triage, reporting
- **Tool reference** — all 20 MCP tools documented by category with decision guidance in instructions
- **Scan profile guide** — quick/standard/thorough selection criteria for Claude
- **Finding interpretation framework** — severity levels, lifecycle states, prioritization strategy
- **Safety constraints** — scope enforcement, authorization checks, user-directed triage
- **`src/mcp/instructions.rs`** — `pub const INSTRUCTIONS` (~4.5KB) referenced by `ServerInfo`
- 5 new tests (4 unit for instruction content validation + 1 integration)

### Changed
- `ServerInfo.instructions` upgraded from 2-line placeholder to comprehensive methodology guide
- MCP server now teaches Claude the complete pentest workflow on connection

## [0.9.0] - 2026-03-29

### Added
- **MCP resources** — browsable read-only resources for project data via MCP protocol
- **Resource URI scheme** — `scorchkit://projects`, `scorchkit://projects/{id}`, `.../scans`, `.../findings` with hierarchical paths
- **5 resource templates** — parameterized URI patterns for project, scan, and finding resources
- **Dynamic resource list** — `list_resources` returns projects collection + per-project resources from database
- **`src/mcp/resources.rs`** — resource business logic with `do_list_resources()`, `do_list_resource_templates()`, `do_read_resource()`
- **URI parser** — `parse_resource_uri()` with `ResourceKind` enum for type-safe dispatch
- 21 new tests (10 unit tests for URI parsing/templates + 11 integration tests for resource operations)

### Changed
- MCP server capabilities now include `resources` alongside `tools`
- `ServerHandler` impl overrides `list_resources`, `list_resource_templates`, `read_resource`

## [0.8.0] - 2026-03-29

### Added
- **Scan scheduling** — `scorchkit schedule create/list/show/enable/disable/delete` for recurring scans per project
- **`schedule run-due`** — explicitly triggers all overdue schedules (wire into system cron for automation)
- **`ScanSchedule` model** — project_id, target_url, profile, cron_expression, enabled, last_run, next_run
- **`storage/schedules.rs`** — CRUD + `find_due_schedules()` + `mark_schedule_run()` + `compute_next_run()`
- **`croner` crate** — lightweight cron expression parsing (5/6/7-field support)
- **Migration `002_scan_schedules.sql`** — `scan_schedules` table with partial index on `next_run WHERE enabled`
- **`schedule-scan` MCP tool** — create recurring scan schedules via MCP (19th tool)
- **`run-due-scans` MCP tool** — trigger due scan execution via MCP (20th tool, was 19)
- 8 new tests (6 storage-gated + 1 mcp-gated + 2 CLI integration)

### Changed
- `Commands` enum now includes `Schedule` subcommand (storage feature-gated)
- MCP server exposes 19 tools (was 17)
- New `croner` dependency added to `storage` feature

## [0.7.0] - 2026-03-29

### Added
- **AI-guided scan planning** — `scorchkit run <url> --plan` runs recon first, then Claude decides which modules to use
- **`ScanPlanner`** — two-phase flow: recon modules gather target intelligence, Claude analyzes findings + module catalog to build a targeted `ScanPlan`
- **`ScanPlan` types** — `ModuleRecommendation` (module_id, priority, rationale), `SkippedModule` (module_id, reason), `PlanValidation`
- **`validate_plan()`** — validates Claude's module recommendations against registered modules, catches hallucinated IDs
- **`plan-scan` MCP tool** — returns structured plan JSON without executing (plan-then-execute workflow)
- **`build_module_catalog()`** — serializes all 41 modules into a compact catalog for Claude's planning prompt
- **`parse_plan_response()`** — multi-tier JSON extractor with empty-plan fallback for graceful degradation
- **Graceful fallback** — if planning fails for any reason, scan continues with standard profile
- 14 new tests (12 default + 1 mcp-gated + 1 CLI integration)

### Changed
- `Commands::Run` now accepts `--plan` flag for AI-guided scanning
- MCP server exposes 17 tools (was 16)
- `run_scan()` restructured to support pre-orchestrator AI planning phase

## [0.6.0] - 2026-03-29

### Added
- **Posture metrics dashboard** — `scorchkit project status <name>` shows security posture at a glance
- **`TrendDirection` enum** — computed trend (Improving/Declining/Stable) from resolved vs active finding ratio
- **Severity breakdown** — finding counts grouped by severity, ordered critical to info
- **Status breakdown** — finding counts grouped by lifecycle status
- **Regression detection** — identifies findings marked remediated/verified that reappeared in the latest scan
- **Top unresolved findings** — top 10 active findings ranked by severity priority
- **`project-status` MCP tool** — returns posture metrics as typed JSON for AI consumption
- **`PostureMetrics` types** — `ScanSummary`, `FindingSummary`, `SeverityCount`, `StatusCount`, `RegressionFinding`, `UnresolvedFinding`
- **`build_posture_metrics()`** — aggregate SQL queries computing all metrics on-the-fly (no new migrations)
- 14 new tests (13 storage-gated + 1 mcp-gated + 1 cli integration)

### Changed
- `ProjectCommands` now includes `Status` subcommand
- MCP server exposes 16 tools (was 15)

## [0.5.0] - 2026-03-28

### Added
- **Structured AI analysis** — typed JSON responses for all 4 analysis modes (summary, prioritize, remediate, filter)
- **17 structured types** — `SummaryAnalysis`, `PrioritizedAnalysis`, `RemediationAnalysis`, `FilterAnalysis` with shared enums (`ExploitabilityRating`, `EffortLevel`, `FindingClassification`)
- **`StructuredAnalysis` enum** — wraps mode-specific types with `Raw` fallback for graceful degradation
- **Multi-tier JSON extractor** — parses Claude responses via direct parse, code fence extraction, balanced block detection, or raw fallback
- **Project history context** — `--project` flag on `analyze` injects scan trends and finding lifecycle stats into AI prompts
- **`analyze-findings` MCP tool** — AI-powered project finding analysis with structured JSON output
- **`ProjectContext` type** — scan history and finding trend data for context-aware analysis
- **`storage::context::build_project_context()`** — aggregates project stats from PostgreSQL
- 23 new tests (8 inline unit + 14 integration + 1 mcp-feature-gated)

### Changed
- `AiAnalysis` struct upgraded from raw text (`content: String`) to typed enum (`StructuredAnalysis`)
- `AnalysisFocus` now derives `Serialize, Deserialize` with snake_case
- `AnalysisFocus::from_str()` renamed to `parse()` to avoid shadowing `FromStr` trait
- AI prompts now request JSON output with documented schemas
- `print_analysis()` renders structured output per mode (risk scores, ranked lists, effort badges, classification tables)

## [0.4.0] - 2026-03-28

### Added
- **MCP server** — `scorchkit serve` starts an MCP server on stdio transport (requires `mcp` feature)
- **15 MCP tools** — list-modules, check-tools, scan, project-create, project-list, project-show, project-delete, project-scan, project-findings, finding-show, finding-update-status, target-add, target-list, target-remove, db-migrate
- **`mcp` Cargo feature** — feature-gated MCP server (implies `storage`), built on `rmcp` v1.3 crate
- **`ScorchKitServer`** — MCP server struct with `ServerHandler` impl and `#[tool_router]` dispatch
- **Parameter types** — `schemars` v1.0 JSON Schema generation for all tool inputs
- 17 new integration tests — one per MCP tool plus server infrastructure tests

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
