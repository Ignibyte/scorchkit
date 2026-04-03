# Changelog

All notable changes to ScorchKit will be documented in this file.

## [0.30.0] - 2026-04-03

### Added
- **Path Traversal / LFI scanner** (`path_traversal`) — Detects directory traversal and local file inclusion via 24 payloads covering depth variations (1-8 levels), URL encoding, double encoding, null byte bypasses, backslash (Windows), UTF-8 overlong encoding, and filter bypass techniques. Matches 12 file content indicators for Linux (`/etc/passwd`, `/etc/shadow`) and Windows (`win.ini`, `boot.ini`, hosts). CWE-22, OWASP A01:2021. `src/scanner/path_traversal.rs` with 7 tests (#70)
- **SSTI scanner** (`ssti`) — Detects server-side template injection across 8 template engines (Jinja2, Twig, Freemarker, ERB, Mako, Velocity, Smarty, Pebble) via 10 safe mathematical expression payloads. Boundary-aware response matching avoids false positives from CSS/pixel values. Engine identification from error messages (19 fingerprints). Tests query params, form fields, and HTTP headers (User-Agent, Referer). CWE-1336, OWASP A03:2021. `src/scanner/ssti.rs` with 7 tests (#70)
- **CRLF injection scanner** (`crlf`) — Detects HTTP response splitting via 7 payload variants: standard `%0d%0a`, double-encoded, unicode, bare LF/CR, Set-Cookie injection, and tab-prefixed. Checks response headers for injected canary headers. CWE-113, OWASP A03:2021. `src/scanner/crlf.rs` with 5 tests (#72)
- **Host header injection scanner** (`host_header`) — Detects host header poisoning via 5 override headers (X-Forwarded-Host, X-Host, X-Forwarded-Server, X-Original-URL, X-Rewrite-URL). Checks response body for reflected canary and HTML attributes (href, src, action) for cache poisoning. CWE-644, OWASP A03:2021/A05:2021. `src/scanner/host_header.rs` with 5 tests (#72)
- **NoSQL injection scanner** (`nosql`) — Detects MongoDB/CouchDB/Redis injection via 12 payloads: `$gt`, `$ne`, `$regex`, `$exists` operators, bracket notation, `$where` JavaScript injection, boolean-based blind. Error-based detection (21 patterns), 500 status detection, response size differential. JSON body injection for auth bypass. CWE-943, OWASP A03:2021. `src/scanner/nosql.rs` with 5 tests (#73)
- **LDAP injection scanner** (`ldap`) — Detects LDAP filter injection via 11 payloads: wildcard, filter-closing, OR injection, null byte, escaped metacharacters. Error-based detection (24 patterns) covering PHP, Java, Python, Active Directory LDAP implementations. CWE-90, OWASP A03:2021. `src/scanner/ldap.rs` with 5 tests (#73)
- **HTTP request smuggling scanner** (`smuggling`) — Heuristic-based CL.TE/TE.CL/TE.TE risk detection via proxy indicator analysis (17 CDN/proxy headers), `Transfer-Encoding` obfuscation variant testing (9 variants), and `Content-Length` handling inconsistency checks. Reports risk indicators with evidence strength-based severity since `reqwest` normalizes TE headers. CWE-444, OWASP A05:2021. `src/scanner/smuggling.rs` with 5 tests (#74)
- Total scanner modules: 31 built-in (was 24)
- Total tests: 384 default (was 345), 520 MCP (was 481)

## [0.29.0] - 2026-03-30

### Changed
- **Final test coverage sweep** — Added 72 new tests across 30 files (#69). Clears entire test backlog.
  - Scanner unit tests: ssl (3), misconfig (3), ratelimit (3), redirect (3), api_schema (3), waf (3)
  - Tool wrapper parser tests: 22 tools × 2 tests (nmap, nuclei, nikto, sqlmap, feroxbuster, sslyze, zap, ffuf, metasploit, wafw00f, testssl, wpscan, amass, subfinder, dalfox, hydra, httpx, theharvester, arjun, cewl, droopescan, interactsh)
  - MCP integration tests: project_status (2), plan_scan (2), analyze_findings (2)
  - Attack chain correlation tests: sqli, ssrf, idor, credential compromise (4)
  - Total: 409→481 tests (MCP), 283→345 tests (default)
- **Test coverage expansion** — Added 88 new tests across 14 files (#68). Scanner coverage 37%→62%, recon 17%→100%, MCP scheduling 0→8 tests.
  - OWASP scanner unit tests: xss (6), ssrf (6), injection (8), cmdi (3), csrf (3), jwt (12), idor (8), sensitive (4)
  - Recon module unit tests: headers (7), tech (5), discovery (9), crawler (6), subdomain (3)
  - MCP scheduling integration tests: `schedule_scan` (4), `run_due_scans` (4)
  - Total: 319→409 tests (MCP), 201→283 tests (default)
- **Clippy zero-warnings cleanup** — Resolved all 185 clippy pedantic/style warnings across 64 files (#67). Zero-warning builds on both default and `--features mcp` configurations.
  - 35 `doc_markdown` backtick fixes in doc comments
  - 23 `manual_let_else` refactors (if-let → let...else)
  - 21 tool wrapper `parse_*_output()` signatures simplified (`Result<Vec<Finding>>` → `Vec<Finding>`)
  - 30 `# Errors` doc sections added to `Result`-returning functions
  - ~76 mixed idiom fixes (or_fun_call, map_or_else, format_push_string, must_use, const_fn, etc.)
  - 4 helper function extractions for too_many_lines (crawler, injection, xss, html)

### Added
- **Deep tool validation** (`doctor --deep`) — Version checks, min-version enforcement, nuclei template freshness, remediation hints for 33 external tools. `src/cli/doctor.rs` with `ToolSpec`, `Version` comparison, 8 new tests (#48)
- **Project init with target fingerprinting** (`init <url>`) — Single HTTP probe detects server, tech stack, CMS, WAF. Recommends scan profile based on detected tech + available tools. Generates tailored `scorchkit.toml`. Optional `--project` flag creates DB project. `src/cli/init.rs` with 10 new tests (#49)
- **Project intelligence layer** — Per-module effectiveness tracking stored in `Project.settings` JSONB (no new migrations). `ModuleStats` per module: runs, findings, severity breakdown, effectiveness score. Updated after each scan. CLI: `project intelligence <name>`. AI planner enhanced with optional historical effectiveness context. `src/storage/intelligence.rs` with 11 new tests (#50)
- **Autonomous scan agent** (`agent <target>`) — 7-phase loop: setup → recon → AI plan → vulnerability scan → AI analyze → persist → report. Calls internal functions directly (Orchestrator, ScanPlanner, AiAnalyst). Graceful AI fallback — plan failure falls back to profile, analysis failure is non-fatal. `src/agent/runner.rs` with 3 new tests (#51)
- 32 new tests total across 4 features

## [0.28.0] - 2026-03-30

### Added
- **Agent SDK support** — `src/agent/` module for autonomous pentest operations via Claude Agent SDK
- **PTES-based agent system prompt** — 7-phase pentest methodology (pre-engagement through remediation) with built-in safety constraints: scope enforcement, no exploitation, evidence preservation, rate limiting
- **AgentConfig** — authorized targets, max scan depth, project persistence, safety constraints. Builder pattern with `with_depth()`, `with_project()`, `with_database_url()`
- **Manifest generator** — `generate_manifest()` produces JSON config for Claude Agent SDK clients (Python/TypeScript) with MCP server connection, system prompt, and safety rules
- 5 new unit tests + 1 doctest

## [0.27.0] - 2026-03-30

### Added
- **Plugin system for user-defined scan modules** — `src/runner/plugin.rs` with TOML-based plugin definitions. Users create `.toml` files defining custom scan modules with command, args (`{target}` placeholder substitution), output format (lines/json_lines/json), and default severity. `PluginModule` implements `ScanModule` trait seamlessly
- **Plugin loader** — `load_plugins()` discovers `.toml` files from configurable `plugins_dir`, validates and registers them alongside built-in modules
- **Orchestrator integration** — plugins auto-loaded in `register_default_modules()` when `plugins_dir` is set in config
- **`plugins_dir`** config option in `ScanConfig` for specifying the plugin directory
- 6 new unit tests (TOML parsing, metadata, arg substitution, line/JSON parsing, empty dir)

## [0.26.0] - 2026-03-30

### Added
- **HTTP evidence capture** — `src/engine/evidence.rs` with `HttpEvidence` struct for capturing full HTTP request/response pairs. Attached to findings via `.with_http_evidence()` builder. Response bodies auto-truncated at 10KB
- **Webhook notifications** — `src/runner/hooks.rs` with `ScanEvent` enum (`ScanStarted`, `ScanCompleted`, `FindingDiscovered`) and `WebhookNotifier`. Async fire-and-forget delivery via `tokio::spawn`. Config via `[[webhooks]]` array with URL + events filter
- **`WebhookConfig`** in `AppConfig` for configuring notification endpoints
- 6 new unit tests (3 evidence + 3 webhook)

## [0.25.0] - 2026-03-30

### Added
- **enum4linux SMB enumeration wrapper** — `src/tools/enum4linux.rs` for share listing, user enumeration via RID cycling, group discovery, and password policy extraction
- **Compliance framework mapping** — `src/engine/compliance.rs` with OWASP/CWE to NIST 800-53, PCI-DSS 4.0, SOC2, HIPAA control mapping. 10 OWASP categories + 13 CWEs mapped
- **Finding `.with_compliance()` builder** — attach compliance framework references to findings
- **Enhanced scope management** — `src/engine/scope.rs` with `ScopeRule` enum supporting exact domain, wildcard (`*.example.com`), and CIDR (`192.168.1.0/24`) matching
- 9 new unit tests (2 enum4linux + 3 compliance + 4 scope)
- ScorchKit now has 63 modules (31 built-in + 32 external tool wrappers)

## [0.24.0] - 2026-03-30

### Added
- **MCP prompt templates** — 5 pentest workflow starting points: `full-web-assessment`, `investigate-finding`, `remediation-plan`, `compare-scans`, `executive-summary`. Exposed via MCP prompts capability (`list_prompts`, `get_prompt`)
- **MCP `correlate_findings` tool** — Rule-based attack chain detection that groups related findings into compound vulnerabilities (e.g., XSS + missing CSP = session hijacking). 6 built-in correlation rules with severity escalation and remediation priority
- **`CorrelateFindingsParams`** type with `JsonSchema` derive
- 9 new tests (5 prompt unit tests + 3 integration tests + 1 correlation test)
- MCP server now exposes 19 tools + 5 prompts

## [0.23.0] - 2026-03-30

### Added
- **Trufflehog secret scanning wrapper** — `src/tools/trufflehog.rs` for detecting leaked API keys, credentials, and tokens in filesystems and git repos
- **Prowler cloud security wrapper** — `src/tools/prowler.rs` for AWS/multi-cloud infrastructure misconfiguration scanning
- **Trivy vulnerability scanning wrapper** — `src/tools/trivy.rs` for container image and dependency vulnerability detection with CVSS severity mapping
- **DNSx DNS toolkit wrapper** — `src/tools/dnsx.rs` for fast DNS resolution, wildcard detection, and record queries
- **Gobuster directory scanner wrapper** — `src/tools/gobuster.rs` for directory and vhost brute-forcing with status-based severity
- **dnsrecon DNS enumeration wrapper** — `src/tools/dnsrecon.rs` for comprehensive DNS enumeration including zone transfer detection
- 12 new unit tests (2 per wrapper for output parsing + empty handling)
- ScorchKit now has 62 modules (31 built-in + 31 external tool wrappers)

## [0.22.0] - 2026-03-30

### Added
- **MCP `auto_scan` composite tool** — One-shot full scan engagement: parse target, apply profile, run modules, optionally persist results to a project with finding deduplication
- **MCP `target_intelligence` composite tool** — Recon-only consolidated briefing: runs all Recon-category modules (headers, tech detection, discovery, subdomain, crawling, DNS) without active vulnerability scanning
- **MCP `scan_progress` status tool** — Post-hoc scan status check: latest scan record with timing, modules, finding count for a project
- 3 new parameter types (`AutoScanParams`, `TargetIntelligenceParams`, `ScanProgressParams`) with `JsonSchema` derives
- 3 new integration tests for parameter deserialization
- MCP server now exposes 18 tools (was 15)

## [0.21.0] - 2026-03-29

### Added
- **Katana web crawler wrapper** — `src/tools/katana.rs` for JS-rendered endpoint discovery via headless browsing
- **Gau passive URL discovery wrapper** — `src/tools/gau.rs` for historical URL collection from Wayback Machine, Common Crawl
- **ParamSpider parameter mining wrapper** — `src/tools/paramspider.rs` for discovering URLs with injectable query parameters
- 6 new unit tests (2 per wrapper for output parsing + empty handling)
- ScorchKit now has 56 modules (31 built-in + 25 external tool wrappers)

## [0.20.0] - 2026-03-29

### Added
- **REST API security testing module** — `src/scanner/api.rs` implementing OWASP API Top 10: mass assignment, excessive data exposure, shadow API discovery, auth endpoint rate limiting, content negotiation confusion
- **DNS & email security recon module** — `src/recon/dns.rs` using DNS-over-HTTPS (Cloudflare `DoH` JSON API): SPF record analysis with permissiveness detection, DMARC policy enforcement check, MX record discovery
- 6 new unit tests (3 API + 3 DNS)
- ScorchKit now has 53 modules (31 built-in + 22 external tool wrappers) and 7 recon modules

## [0.19.0] - 2026-03-29

### Added
- **Professional PDF pentest report generation** — `src/report/pdf.rs` with `--format pdf` CLI flag
- **6-section professional layout** — cover page, executive summary with risk rating, scope & methodology, risk matrix, detailed findings with evidence/remediation/OWASP/CWE, appendix with module list
- **Print-optimized CSS** — A4 page size, `@page` rules with page numbers, page breaks per section, professional color scheme
- **`weasyprint` integration** — HTML-to-PDF conversion via subprocess with stdin piping (no temp files)
- **`OutputFormat::Pdf`** variant in CLI args with dispatch in runner
- 8 new unit tests for HTML template structure, severity counts, finding details, print CSS, risk matrix, risk rating, categories, HTML escaping
- ScorchKit now supports 5 output formats: terminal, json, html, sarif, pdf

## [0.18.0] - 2026-03-29

### Added
- **Subdomain takeover detection module** — `src/scanner/subtakeover.rs` probing 15 common subdomains against 8 cloud provider fingerprints (GitHub Pages, Heroku, AWS S3, Azure, Shopify, Fastly, Pantheon, Tumblr)
- **Access control testing module** — `src/scanner/acl.rs` testing admin path discovery (20 paths), HTTP method override bypass, path traversal auth bypass (8 variants), and forced browsing to sequential API resource IDs
- 7 new unit tests (4 subtakeover + 3 ACL)
- ScorchKit now has 51 modules (29 built-in + 22 external tool wrappers)

## [0.17.0] - 2026-03-29

### Added
- **CORS deep analysis module** — `src/scanner/cors.rs` testing subdomain wildcards, internal network origin bypass, preflight cache abuse, method allowlist analysis, sensitive header exposure
- **CSP bypass detection module** — `src/scanner/csp.rs` testing missing critical directives (`base-uri`, `object-src`, `frame-ancestors`), permissive `script-src` (`data:`, `blob:`, `https:`), `report-uri` information leaks, wildcard `default-src`
- First merged pipeline — two modules (#16 + #17) in one pipeline
- 12 new unit tests (5 CORS + 7 CSP)
- ScorchKit now has 49 modules (27 built-in + 22 external tool wrappers)

## [0.16.0] - 2026-03-29

### Added
- **GraphQL deep security testing module** — `src/scanner/graphql.rs` implementing `GraphQLModule`
- **GraphQL endpoint discovery** — probes 10 common paths (`/graphql`, `/api/graphql`, `/gql`, etc.) via `{ __typename }` query
- **Introspection detection** — tests if full schema introspection is enabled, counts exposed types
- **Query depth abuse** — sends 15-level nested queries to detect missing depth limits
- **Batch query abuse** — tests batch query support (25 queries in one request) for DoS potential
- **Field suggestion leaks** — detects "Did you mean" information disclosure on misspelled fields
- **Mutation enumeration** — discovers exposed mutations via targeted introspection
- 8 new unit tests for query building, response analysis, and endpoint detection
- ScorchKit now has 46 modules (25 built-in + 22 external tool wrappers) — milestone: 100 default tests

## [0.15.0] - 2026-03-29

### Added
- **WebSocket security testing module** — `src/scanner/websocket.rs` implementing `WebSocketModule`
- **WS endpoint discovery** — probes 19 common WebSocket paths (`/ws`, `/socket.io`, `/cable`, `/hub`, `/signalr`, `/graphql`, etc.)
- **CSWSH detection** — Cross-Site WebSocket Hijacking via spoofed Origin header validation
- **Unencrypted WS detection** — flags `ws://` endpoints when HTTPS is available
- **Unauthenticated WS access** — detects WebSocket endpoints accepting connections without credentials
- **`tokio-tungstenite`** — new async WebSocket client dependency (MIT/Apache-2.0, `rustls-tls-native-roots` feature)
- 6 new unit tests for URL conversion, path generation, upgrade response detection
- ScorchKit now has 45 modules (23 built-in + 22 external tool wrappers)

## [0.14.0] - 2026-03-29

### Added
- **File upload vulnerability testing module** — `src/scanner/upload.rs` implementing `UploadModule`
- **Upload form discovery** — HTML parsing for `<input type="file">` with action URL resolution and hidden field extraction
- **9 upload bypass payloads** — PHP, JSP, double extension (.php.jpg), content-type mismatch, polyglot GIF+PHP, null byte filename, path traversal, SVG XSS, HTML upload
- **Heuristic acceptance detection** — status code + body keyword analysis to determine if uploads were accepted
- 8 new unit tests for form discovery, payload generation, acceptance heuristic
- ScorchKit now has 44 modules (22 built-in + 22 external tool wrappers)

### Changed
- `reqwest` dependency now includes `multipart` feature for file upload submission

## [0.13.0] - 2026-03-29

### Added
- **Authentication & session management testing module** — `src/scanner/auth.rs` implementing `AuthSessionModule`
- **Session ID entropy analysis** — Shannon entropy scoring to detect predictable session IDs (< 3.0 bits/char threshold)
- **Session fixation detection** — compares pre-auth vs post-auth session cookies to detect unchanged session IDs
- **Logout invalidation testing** — probes common logout paths then verifies session is actually invalidated
- **Session expiry analysis** — flags excessive `Max-Age` (> 24h) and far-future `Expires` dates
- **Multiple session cookie detection** — identifies fragmented session management (> 1 session cookie)
- **Credential-gated tests** — fixation and logout require `AuthConfig` credentials; passive checks run regardless
- 11 new unit tests for entropy, fixation, expiry, cookie parsing, credential detection
- ScorchKit now has 43 modules (21 built-in + 22 external tool wrappers)

## [0.12.0] - 2026-03-29

### Added
- **Interactsh OOB callback integration** — detect blind SSRF, XXE, RCE, and SQLi via out-of-band callbacks
- **`src/engine/oob.rs`** — shared OOB infrastructure: `InteractshSession` (subprocess lifecycle), `OobInteraction` (callback data), `BlindPayload`/`BlindCategory` (payload templates), correlation matching
- **`src/tools/interactsh.rs`** — `InteractshModule` implementing `ScanModule` with `requires_external_tool("interactsh-client")`
- 4 blind vulnerability categories with targeted payloads: SSRF (URL injection), XXE (entity injection), RCE (command injection via nslookup/curl/backtick), SQLi (DNS exfiltration via LOAD_FILE)
- Correlation via subdomain prefix: `{correlation_id}.{base_domain}` matches callbacks to originating payloads
- 10 new unit tests for interaction parsing, URL generation, correlation matching, payload generation
- ScorchKit now has 42 modules (20 built-in + 22 external tool wrappers)

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
