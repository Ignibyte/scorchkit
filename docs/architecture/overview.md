# ScorchKit Architecture Overview

ScorchKit is a modular web application security testing toolkit written in Rust. It operates as both a native scanner (built-in Rust modules that perform security checks directly) and an orchestrator (wrapping and coordinating external pentesting tools behind a unified interface). The tool targets OWASP Top 10 web vulnerabilities and integrates Claude AI for intelligent analysis, planning, and autonomous operation.

---

## 1. System Architecture

```
                    ┌──────────────────┐    ┌─────────────────┐
                    │  CLI (clap)      │    │  MCP Server     │
                    │  args.rs         │    │  (rmcp stdio)   │
                    │                  │    │  24 tools       │
                    │  run, recon,     │    │  6 resources    │
                    │  scan, analyze,  │    │  5 prompts      │
                    │  diff, agent,    │    └────────┬────────┘
                    │  init, doctor,   │             │
                    │  modules, db,    │             │
                    │  serve, schedule │             │
                    └────────┬─────────┘             │
                             │                       │
                             └───────────┬───────────┘
                                         │
                       ┌─────────────────▼──────────────────┐
                       │           Orchestrator              │
                       │         orchestrator.rs             │
                       │                                     │
                       │  Semaphore(max_concurrent_modules)  │
                       │                                     │
                       │  ┌─────────┐ ┌─────────┐ ┌───────┐ │
                       │  │ Recon   │ │ Scanner │ │ Tools │ │  ScanModule trait
                       │  │ (10)   │ │ (35)    │ │ (32)  │ │
                       │  └────┬────┘ └────┬────┘ └───┬───┘ │
                       └───────┼───────────┼──────────┼─────┘
                               │           │          │
                      ┌────────▼───┐  ┌────▼────┐  ┌──▼───────────┐
                      │  Built-in  │  │  HTTP   │  │  Subprocess  │
                      │  Analysis  │  │  Reqs   │  │  Execution   │
                      │  (Rust)    │  │(reqwest)│  │  (external)  │
                      └────────┬───┘  └────┬────┘  └──┬───────────┘
                               │           │          │
                               └───────────┼──────────┘
                                           │
                                    ┌──────▼───────┐
                                    │  ScanResult  │
                                    │ Vec<Finding> │
                                    └──────┬───────┘
                                           │
              ┌────────────────────────────┬┼────────────────────────────┐
              │                            ││                            │
    ┌─────────▼─────────┐    ┌─────────────▼▼────────────┐    ┌────────▼────────┐
    │     Reports       │    │      AI Analysis         │    │     Storage     │
    │                   │    │                           │    │                 │
    │  Terminal (color) │    │  AiAnalyst  (analyze)    │    │  PostgreSQL     │
    │  JSON  (file)     │    │  ScanPlanner (plan)      │    │  (sqlx, async)  │
    │  HTML  (styled)   │    │  AgentRunner (auto)      │    │                 │
    │  SARIF (CI/CD)    │    │                           │    │  Projects       │
    │  PDF   (pentest)  │    │  Claude CLI subprocess   │    │  Scans          │
    │  Diff  (compare)  │    │  Structured JSON output  │    │  Findings       │
    └───────────────────┘    └───────────────────────────┘    │  Schedules      │
                                                              │  Intelligence   │
                                                              └─────────────────┘
```

The CLI and MCP server are two entry points into the same engine. The CLI dispatches commands directly; the MCP server exposes the same operations as tools that AI assistants call conversationally. Both share the Orchestrator for scanning and the Storage layer for persistence.

### Data Flow

1. User invokes `scorchkit run <target>` with optional flags (or MCP client calls `scan-target`)
2. CLI parses arguments via clap, loads `AppConfig` from TOML with CLI flag overrides
3. `Target` is parsed from the input string (URL, domain, or IP; bare domains default to HTTPS)
4. `ScanContext` is built: `Target` + `Arc<AppConfig>` + `reqwest::Client` + `Arc<SharedData>`
5. `Orchestrator` discovers modules via `all_modules()`, applies filters (category, profile, include, exclude)
6. Orchestrator checks external tool availability, skips unavailable modules with reason
7. Modules run concurrently (up to `max_concurrent_modules` via tokio `Semaphore`), each returning `Vec<Finding>`
8. Findings are aggregated, sorted by severity (critical first)
9. `ScanResult` is constructed with findings, metadata, and `ScanSummary` stats
10. Reports are generated: JSON saved to disk, terminal output printed, optional HTML/SARIF/PDF
11. (Optional) AI analysis via Claude CLI subprocess
12. (Optional) Database persistence via storage layer with fingerprint deduplication

---

## 2. Module System

### The ScanModule Trait

Every module in ScorchKit implements this trait, whether it performs built-in analysis or wraps an external tool:

```rust
#[async_trait]
pub trait ScanModule: Send + Sync {
    fn name(&self) -> &str;              // Human-readable display name
    fn id(&self) -> &str;                // Short identifier for CLI/config
    fn category(&self) -> ModuleCategory; // Recon or Scanner
    fn description(&self) -> &str;       // Brief check description
    async fn run(&self, ctx: &ScanContext) -> Result<Vec<Finding>>;

    // External tool support (default: false/None)
    fn requires_external_tool(&self) -> bool { false }
    fn required_tool(&self) -> Option<&str> { None }
}
```

`ModuleCategory` has two variants: `Recon` and `Scanner`. Recon modules gather intelligence without active exploitation; scanner modules perform active vulnerability detection.

### Module Categories

ScorchKit ships with 77 built-in modules plus user plugins:

| Category | Count | Purpose | Registration |
|----------|-------|---------|--------------|
| **Recon** | 10 | Information gathering | `recon::register_modules()` |
| **Scanner** | 35 | Active vulnerability detection | `scanner::register_modules()` |
| **Tools** | 32 | External tool wrappers | `tools::register_modules()` |
| **Plugins** | variable | User-defined via TOML | `plugin::load_plugins()` |

**Recon modules** (10): headers, tech, discovery, subdomain, crawler, dns, js-analysis, cname-takeover, vhost, cloud.

**Scanner modules** (35): auth, cors, csp, waf, ssl, misconfig, csrf, injection, cmdi, xss, ssrf, xxe, idor, jwt, redirect, sensitive, upload, websocket, graphql, subtakeover, acl, api, api-schema, ratelimit, path-traversal, ssti, crlf, host-header, nosql, ldap, smuggling, prototype-pollution, mass-assignment, clickjacking, dom-xss.

**Tool wrappers** (32): interactsh, nmap, nuclei, nikto, sqlmap, feroxbuster, sslyze, zap, ffuf, metasploit, wafw00f, testssl, wpscan, amass, subfinder, dalfox, hydra, httpx, theharvester, arjun, cewl, droopescan, katana, gau, paramspider, trufflehog, prowler, trivy, dnsx, gobuster, dnsrecon, enum4linux.

### Module Registration

Modules self-register in their category's `register_modules()` function:

```rust
// src/recon/mod.rs
pub fn register_modules() -> Vec<Box<dyn ScanModule>> {
    vec![
        Box::new(headers::HeadersModule),
        Box::new(tech::TechModule),
        // ...
    ]
}
```

The orchestrator collects all modules via `all_modules()`:

```rust
pub fn all_modules() -> Vec<Box<dyn ScanModule>> {
    let mut modules: Vec<Box<dyn ScanModule>> = Vec::new();
    modules.extend(crate::recon::register_modules());
    modules.extend(crate::scanner::register_modules());
    modules.extend(crate::tools::register_modules());
    modules
}
```

User plugins are loaded separately from a configurable plugins directory (`scan.plugins_dir`) during `register_default_modules()`.

### Plugin System

User-defined modules are declared in TOML files:

```toml
id = "custom-check"
name = "My Custom Check"
description = "Runs a custom security check"
category = "scanner"
command = "my-tool"
args = ["--json", "{target}"]
timeout_seconds = 120
output_format = "json_lines"    # "lines", "json_lines", or "json"
severity = "medium"
```

The `{target}` placeholder is substituted with the scan target URL at runtime. Output formats determine how stdout is parsed into findings: `lines` consolidates all output into one finding, `json_lines` treats each line as a JSON object, and `json` parses a single JSON array.

---

## 3. Finding Model

The `Finding` struct is the universal data currency. Modules produce findings, the orchestrator collects them, AI analyzes them, the storage layer deduplicates them, and reports render them.

### Struct Fields

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `module_id` | `String` | yes | Which module produced this finding |
| `severity` | `Severity` | yes | Critical, High, Medium, Low, Info |
| `title` | `String` | yes | Short title (e.g., "Missing HSTS Header") |
| `description` | `String` | yes | Detailed description of the issue |
| `affected_target` | `String` | yes | The affected URL, header, parameter, etc. |
| `evidence` | `Option<String>` | no | Raw evidence (response snippet, header value) |
| `remediation` | `Option<String>` | no | Suggested fix |
| `owasp_category` | `Option<String>` | no | OWASP reference (e.g., "A05:2021") |
| `cwe_id` | `Option<u32>` | no | CWE identifier |
| `compliance` | `Option<Vec<String>>` | no | NIST, PCI-DSS, SOC2, HIPAA controls |
| `http_evidence` | `Option<HttpEvidence>` | no | Full HTTP request/response pair for PoC replay |
| `confidence` | `f64` | yes | 0.0-1.0 score (default 0.5); higher = more certain true positive |
| `timestamp` | `DateTime<Utc>` | yes | When found (auto-set) |

### Confidence Scores

Every finding carries a confidence score from 0.0 to 1.0 indicating how likely it is a true positive. The default is 0.5 (unknown detection strength). Values are clamped to the valid range via `with_confidence()`. The `ScanResult::filter_by_confidence()` method removes findings below a threshold and recomputes the summary.

### Builder Pattern

Findings use a fluent builder pattern with `#[must_use]` methods:

```rust
Finding::new("xss", Severity::High, "Reflected XSS", "Script tag reflected", "https://example.com/search")
    .with_evidence("Parameter: q | Payload: <script>alert(1)</script>")
    .with_remediation("HTML-encode user input before rendering")
    .with_owasp("A03:2021")
    .with_cwe(79)
    .with_confidence(0.9)
    .with_compliance(compliance_for_owasp("A03"))
    .with_http_evidence(HttpEvidence::new("GET", "https://example.com/search?q=<script>", 200)
        .with_response_body("<html>...<script>alert(1)</script>...</html>"))
```

### Severity Levels

`Severity` follows CVSS-style classification and implements `Ord` for sorting:

```
Info < Low < Medium < High < Critical
```

### HTTP Evidence

`HttpEvidence` captures full HTTP request/response pairs for proof-of-concept replay. Response bodies are automatically truncated to 10KB (`MAX_BODY_SIZE`) with a `truncated` flag. Fields: method, url, request_headers, request_body, status_code, response_headers, response_body.

### Compliance Mapping

The `engine/compliance.rs` module maps OWASP Top 10 categories and CWE identifiers to compliance framework controls across NIST 800-53, PCI-DSS 4.0, SOC2 TSC, and HIPAA. Findings carry compliance references via `.with_compliance()`.

---

## 4. Execution Model

The `Orchestrator` struct coordinates module execution and provides three execution strategies.

### Concurrent Execution (`run`)

The default mode runs all modules concurrently, bounded by a tokio `Semaphore`:

```
Semaphore(max_concurrent_modules=4)
    │
    ├── Module A (acquire permit → run → release)
    ├── Module B (acquire permit → run → release)
    ├── Module C (acquire permit → run → release)
    └── ... (blocked until permit available)
```

Each module receives a shared `ScanContext` (clone-cheap via `Arc`) and returns `Result<Vec<Finding>>`. Errors are captured per-module, not propagated -- a failing module is recorded in `modules_skipped` and the scan continues. External tool availability is checked before execution; unavailable tools are skipped with a reason.

### Phased Execution (`run_phased`)

Phased mode runs modules in two waves, enabling inter-module data sharing:

```
Phase 1: Recon modules (concurrent)
    │
    │  Publish: URLs, forms, params, technologies, subdomains
    │  via SharedData
    │
    ▼
Phase 2: Scanner + Tool modules (concurrent)
    │
    │  Consume: SharedData from recon phase
    │
    ▼
Merged ScanResult
```

Modules are partitioned by `ModuleCategory`. All recon modules complete before any scanner modules start, so scanner modules can read discovered data (URLs, forms, technologies) from `SharedData`.

### Checkpoint/Resume (`run_with_checkpoint`)

Long-running scans can be interrupted and resumed:

1. Before execution, a `ScanCheckpoint` is created with scan_id, target, profile, and a config hash
2. After each module completes, the checkpoint is serialized to a JSON file on disk
3. The checkpoint records `completed_modules` and accumulated `findings`
4. If a scan is interrupted, `--resume <file>` reloads the checkpoint
5. Already-completed modules are skipped; their findings are merged into the result
6. A config hash detects if the scan configuration changed between runs
7. On successful completion, the checkpoint file is deleted

Checkpoint file format: `.scorchkit-checkpoint-{scan_id}.json` in the output directory.

### Module Filtering

The orchestrator provides several filtering methods before execution:

| Method | Purpose |
|--------|---------|
| `filter_by_category(ModuleCategory)` | Keep only recon or scanner modules |
| `filter_by_ids(&[String])` | Keep only modules matching these IDs |
| `exclude_by_ids(&[String])` | Remove modules matching these IDs |
| `apply_profile("quick"/"standard"/"thorough")` | Apply scan profile rules |

Profiles: `quick` keeps only `headers`, `tech`, `ssl`, `misconfig` (fast, built-in only). `standard` and `thorough` keep all modules.

---

## 5. Inter-Module Data Sharing

### SharedData

`SharedData` is a thread-safe key-value store (`RwLock<HashMap<String, Vec<String>>>`) that enables inter-module communication. It lives inside `ScanContext` behind an `Arc`.

```rust
pub struct ScanContext {
    pub target: Target,
    pub config: Arc<AppConfig>,
    pub http_client: reqwest::Client,
    pub shared_data: Arc<SharedData>,
}
```

### Well-Known Keys

```rust
pub mod keys {
    pub const URLS: &str = "urls";                // URLs discovered by crawler
    pub const FORMS: &str = "forms";              // Form endpoint URLs
    pub const PARAMS: &str = "params";            // Query parameter names
    pub const TECHNOLOGIES: &str = "technologies"; // Detected tech identifiers
    pub const SUBDOMAINS: &str = "subdomains";    // Discovered subdomains
}
```

### Producers and Consumers

| Key | Producers | Consumers |
|-----|-----------|-----------|
| `urls` | Crawler module | XSS, injection, SSRF, path traversal, SSTI, CRLF, and other scanners |
| `forms` | Crawler module | CSRF, injection, mass assignment modules |
| `params` | Crawler module | Parameter-based injection scanners |
| `technologies` | Tech fingerprinting module | Technology-specific scanner modules |
| `subdomains` | Subdomain enumeration module | Subdomain takeover, CNAME takeover modules |

### API

- `publish(key, values)` -- Thread-safe write; extends existing entries. Empty values are a no-op.
- `get(key) -> Vec<String>` -- Thread-safe read; returns empty vec for missing keys.
- `has(key) -> bool` -- Check if any data exists for a key.

This data flow is why `run_phased()` exists: recon modules must complete and publish data before scanner modules can consume it.

---

## 6. Configuration Hierarchy

Configuration is resolved with strict precedence: CLI flags > config.toml > defaults.

### Precedence

```
CLI flags (--proxy, --profile, --scope, --insecure, ...)
    │
    ▼  override
config.toml (loaded via --config or default path)
    │
    ▼  override
Compiled defaults (ScanConfig::default(), etc.)
```

### AppConfig Structure

```
AppConfig
├── scan: ScanConfig
│   ├── timeout_seconds: 300
│   ├── max_concurrent_modules: 4
│   ├── user_agent: "ScorchKit/{version}"
│   ├── follow_redirects: true
│   ├── max_redirects: 10
│   ├── headers: HashMap<String, String>
│   ├── rate_limit: 0 (unlimited)
│   ├── profile: "standard"
│   ├── proxy: Option<String>
│   ├── scope_include: Vec<String>
│   ├── scope_exclude: Vec<String>
│   ├── plugins_dir: Option<PathBuf>
│   └── insecure: false
├── auth: AuthConfig
│   ├── bearer_token: Option<String>
│   ├── cookies: Option<String>
│   ├── username/password: Option<String>
│   └── custom_header/custom_header_value: Option<String>
├── tools: ToolsConfig
│   └── {tool_name}: Option<String>  (binary path overrides for 21 tools)
├── ai: AiConfig
│   ├── enabled: true
│   ├── claude_binary: "claude"
│   ├── model: "sonnet"
│   ├── max_budget_usd: 0.50
│   └── auto_analyze: false
├── report: ReportConfig
│   ├── output_dir: "./reports"
│   ├── include_evidence: true
│   └── include_remediation: true
├── database: DatabaseConfig
│   ├── url: Option<String>
│   ├── max_connections: 5
│   └── migrate_on_startup: true
├── wordlists: WordlistConfig
│   ├── directory: Option<PathBuf>
│   ├── subdomain: Option<PathBuf>
│   ├── vhost: Option<PathBuf>
│   └── params: Option<PathBuf>
└── webhooks: Vec<WebhookConfig>
    ├── url: String
    └── events: Vec<String>  (filter: scan_started, scan_completed, finding_discovered)
```

### Loading

`AppConfig::load(path)` reads a TOML file and deserializes it. All sections use `#[serde(default)]` so partial configs are valid. The CLI runner then applies flag overrides (proxy, scope, profile, insecure, etc.) on top of the loaded config.

### Scope Management

Scope rules support three matching modes: exact domain (`example.com`), wildcard (`*.example.com`), and CIDR range (`192.168.1.0/24`). Rules are parsed from `--scope`/`--exclude` flags or `scope_include`/`scope_exclude` config arrays.

---

## 7. Report Pipeline

`ScanResult` flows into six output formats:

```
ScanResult
    │
    ├── Terminal ─── print_report() ──────── Colored terminal output with severity badges
    │                                        Confidence percentages, evidence, remediation
    │
    ├── JSON ─────── save_report() ────────► ./reports/scorchkit-{scan_id}.json
    │                                        Full serde serialization of ScanResult
    │
    ├── HTML ─────── save_report() ────────► ./reports/scorchkit-{scan_id}.html
    │                                        Self-contained dark-themed HTML with CSS
    │                                        Severity-colored cards, confidence badges
    │                                        Print media query for paper output
    │
    ├── SARIF ────── save_report() ────────► ./reports/scorchkit-{scan_id}.sarif
    │                                        SARIF v2.1.0 for GitHub Advanced Security,
    │                                        Azure DevOps. Maps severity to error/warning/note.
    │                                        Confidence mapped to SARIF rank (0-100).
    │                                        CWE relationships, OWASP tags.
    │
    ├── PDF ──────── save_report() ────────► ./reports/scorchkit-{scan_id}.pdf
    │                                        Professional pentest report via weasyprint.
    │                                        Cover page, executive summary, methodology,
    │                                        risk matrix, finding details, appendix.
    │                                        Print-optimized A4 CSS with page breaks.
    │
    └── Diff ─────── print_diff() ─────────  Compare two ScanResults: new findings,
                                             resolved findings, unchanged count, trend.
                                             Matches on (title, affected_target) pairs.
```

### ScanResult Structure

```rust
pub struct ScanResult {
    pub scan_id: String,
    pub target: Target,
    pub started_at: DateTime<Utc>,
    pub completed_at: DateTime<Utc>,
    pub findings: Vec<Finding>,
    pub modules_run: Vec<String>,
    pub modules_skipped: Vec<(String, String)>,  // (module_id, reason)
    pub summary: ScanSummary,                    // total, critical, high, medium, low, info
}
```

`ScanSummary` is computed from findings at construction time. `filter_by_confidence(min)` removes low-confidence findings and recomputes the summary.

---

## 8. Storage Layer

The storage layer provides persistent PostgreSQL storage for projects, scans, findings, schedules, and intelligence. It is feature-gated behind the `storage` Cargo feature.

### Database Schema

```
projects
├── id: UUID (PK)
├── name: VARCHAR (unique)
├── description: TEXT
├── settings: JSONB (includes intelligence data)
├── created_at, updated_at: TIMESTAMPTZ

project_targets
├── id: UUID (PK)
├── project_id: UUID (FK → projects)
├── url: VARCHAR
├── label: VARCHAR
├── created_at: TIMESTAMPTZ

scan_records
├── id: UUID (PK)
├── project_id: UUID (FK → projects)
├── target_url, profile: VARCHAR
├── started_at, completed_at: TIMESTAMPTZ
├── modules_run, modules_skipped: TEXT[]
├── summary: JSONB
├── created_at: TIMESTAMPTZ

tracked_findings
├── id: UUID (PK)
├── scan_id: UUID (FK → scan_records)
├── project_id: UUID (FK → projects)
├── fingerprint: VARCHAR (SHA-256 dedup hash)
├── module_id, severity, title, description: VARCHAR/TEXT
├── affected_target, evidence, remediation: TEXT
├── owasp_category: VARCHAR, cwe_id: INT
├── raw_finding: JSONB
├── confidence: FLOAT8
├── first_seen, last_seen: TIMESTAMPTZ
├── seen_count: INT
├── status: VARCHAR (new/acknowledged/false_positive/wont_fix/accepted_risk/remediated/verified)
├── status_note: TEXT
├── found_at: TIMESTAMPTZ

scan_schedules
├── id: UUID (PK)
├── project_id: UUID (FK → projects)
├── target_url, profile, cron_expression: VARCHAR
├── enabled: BOOLEAN
├── last_run, next_run: TIMESTAMPTZ
├── created_at: TIMESTAMPTZ
```

### Finding Deduplication

Findings are deduplicated using a SHA-256 fingerprint of `module_id || title || affected_target`. This deliberately excludes evidence and timestamp, so the same vulnerability found across multiple scans maps to the same tracked finding. On duplicate, `seen_count` is incremented and `last_seen` is updated rather than creating a new row.

### Vulnerability Lifecycle

Tracked findings progress through a lifecycle:

```
New → Acknowledged → Remediated → Verified
  │                     │
  ├→ False Positive     ├→ Won't Fix
  └→ Accepted Risk      └→ Accepted Risk
```

The `VulnStatus` enum: `New`, `Acknowledged`, `FalsePositive`, `WontFix`, `AcceptedRisk`, `Remediated`, `Verified`.

### Project Intelligence

Per-module effectiveness statistics are accumulated across scans in the `Project.settings` JSONB field (no additional tables needed):

- `ModuleStats`: total_runs, total_findings, severity breakdown, effectiveness_score (findings/runs)
- `TargetProfile`: server, technologies, CMS, WAF, is_https
- `ProjectIntelligence`: module stats map, target profile, total_scans, last_updated

Intelligence data is used by the AI planner to make data-driven module selection decisions. The `format_for_planner()` method produces a compact text summary injected into Claude prompts.

### Posture Metrics

The `storage/metrics.rs` module computes aggregate security posture metrics on-the-fly via SQL queries. `TrendDirection` (Improving/Declining/Stable) is computed from the ratio of resolved to active findings.

### Connection Precedence

Database URL resolution follows a three-level precedence:

1. `--database-url` CLI flag
2. `config.toml` `[database]` section `url` field
3. `DATABASE_URL` environment variable

Migrations are embedded at compile time via `sqlx::migrate!()` and run automatically on startup when `migrate_on_startup` is true (default).

---

## 9. AI Integration

ScorchKit integrates with Claude via the `claude` CLI binary as a subprocess. AI features are non-blocking -- failures fall back gracefully.

### AiAnalyst (Post-Scan Analysis)

Analyzes scan findings with four structured modes:

| Focus | Output Type | Description |
|-------|-------------|-------------|
| `summary` | `SummaryAnalysis` | Risk score (0-10), executive summary, key findings, attack surface, business impact |
| `prioritize` | `PrioritizedAnalysis` | Findings ranked by exploitability, attack chains, recommended fix order |
| `remediate` | `RemediationAnalysis` | Ordered remediation steps with code examples, effort estimates (trivial to major), verification steps |
| `filter` | `FilterAnalysis` | False positive classification (confirmed, likely true, uncertain, likely FP, false positive) with confidence scores |

Each mode produces a typed `StructuredAnalysis` variant. If JSON parsing fails, the response falls back to `StructuredAnalysis::Raw { content }`. Analysis results include cost tracking (`cost_usd`) and model identification.

When a project is available, `ProjectContext` (scan history, finding trends, status breakdown) is injected into the prompt for trend-aware analysis.

### ScanPlanner (Pre-Scan Planning)

AI-guided scan planning uses a two-phase approach:

1. **Recon phase**: Runs all recon modules to gather target intelligence
2. **Planning phase**: Sends recon findings + full module catalog to Claude
3. **Validation**: Claude returns a `ScanPlan` with `ModuleRecommendation` entries; unknown module IDs are filtered out
4. **Execution**: The orchestrator runs only the recommended modules

The scan plan includes: recommended modules with priority and rationale, skipped modules with reasons, overall strategy description, and estimated scan time.

### Autonomous Agent

The `agent` command drives the full loop: `setup -> recon -> plan -> scan -> analyze -> persist`.

```
Phase 1: Setup      — Parse target, validate, configure
Phase 2: Recon      — Run recon modules, gather intelligence
Phase 3: AI Plan    — Claude analyzes recon, selects modules (fallback: profile-based)
Phase 4: Scan       — Run selected modules concurrently
Phase 5: AI Analyze — Claude provides executive summary (non-fatal on failure)
Phase 6: Persist    — Save JSON report, persist to database (if --project set)
```

Each phase is independent. AI failures in planning fall back to profile-based scanning. AI failures in analysis are logged but non-fatal. Database persistence is optional (requires `--project` flag and `storage` feature).

---

## 10. MCP Server

The MCP (Model Context Protocol) server exposes ScorchKit as an MCP service over stdio transport, built on the `rmcp` crate. It requires both the `storage` and `mcp` feature flags. Started via `scorchkit serve`.

### Server Architecture

```rust
pub struct ScorchKitServer {
    config: Arc<AppConfig>,
    pool: PgPool,
    tool_router: ToolRouter<Self>,
}
```

The server implements `ServerHandler` with capabilities: tools, resources, and prompts.

### Tools (24)

| Tool | Description |
|------|-------------|
| `list-modules` | List all available scan modules |
| `check-tools` | Check external tool installation |
| `scan-target` | Scan a URL without project persistence |
| `plan-scan` | AI-guided scan planning |
| `create-project` | Create a security assessment project |
| `list-projects` | List all projects |
| `get-project` | Get project details |
| `delete-project` | Delete project and all associated data |
| `project-scan` | Scan within a project (auto-persist) |
| `list-findings` / `get-finding` | Query tracked findings |
| `update-finding-status` | Transition finding lifecycle status |
| `add-target` / `list-targets` / `remove-target` | Manage project targets |
| `schedule-scan` / `list-schedules` / `run-due-scans` | Recurring scan schedules |
| `project-status` | Security posture metrics |
| `analyze-findings` | AI analysis with project context |
| `auto-scan` | One-call complete scan (parse, profile, scan, persist) |
| `target-intelligence` | Recon-only modules for intelligence gathering |
| `scan-progress` | Status of most recent scan |
| `correlate-findings` | Analyze findings for attack chains |

### Resources (6)

All resources use the `scorchkit://` URI scheme:

| URI | Description |
|-----|-------------|
| `scorchkit://projects` | List all projects |
| `scorchkit://projects/{id}` | Project details with scan/finding counts |
| `scorchkit://projects/{id}/scans` | Scan history |
| `scorchkit://projects/{id}/scans/{scan_id}` | Single scan record |
| `scorchkit://projects/{id}/findings` | Tracked findings |
| `scorchkit://projects/{id}/findings/{finding_id}` | Single finding |

Five resource templates define the parameterized URI patterns for client discovery.

### Prompts (5)

| Prompt | Description |
|--------|-------------|
| `full-web-assessment` | Complete security assessment against a target |
| `investigate-finding` | Deep dive into a specific finding |
| `remediation-plan` | Prioritized remediation plan for a project |
| `compare-scans` | Analyze changes between two scans |
| `executive-summary` | Client-ready executive summary |

### Agent SDK Support

The `agent/` module generates JSON manifests for Claude Agent SDK consumption:

```json
{
  "name": "scorchkit-agent",
  "mcp_server": { "command": "scorchkit", "args": ["serve"], "transport": "stdio" },
  "system_prompt": "...",
  "agent_config": { "authorized_targets": [...], "max_depth": "standard" },
  "safety": { "scope_enforcement": "strict", "exploitation": "disabled" }
}
```

The manifest includes safety constraints (authorized targets, scope enforcement, no exploitation) and the pentest methodology system prompt.

---

## 11. Feature Flags

ScorchKit uses Cargo features to gate optional subsystems:

```toml
[features]
default = []                              # CLI-only, no database, no MCP
storage = ["dep:sqlx", "dep:sha2", "dep:croner"]  # PostgreSQL persistence
mcp = ["storage", "dep:rmcp", "dep:schemars"]      # MCP server (implies storage)
```

### Build Configurations

| Build | Command | Modules | Storage | MCP | Test Count |
|-------|---------|---------|---------|-----|------------|
| Default | `cargo build` | All 77 scan modules | No | No | ~178 |
| Storage | `cargo build --features storage` | All + DB persistence | Yes | No | ~230 |
| Full | `cargo build --features mcp` | All + DB + MCP server | Yes | Yes | ~287 |

### Feature-Gated Code

```rust
// src/lib.rs
pub mod engine;       // Always available
pub mod cli;          // Always available
pub mod recon;        // Always available
pub mod scanner;      // Always available
pub mod tools;        // Always available
pub mod ai;           // Always available
pub mod agent;        // Always available
pub mod runner;       // Always available
pub mod report;       // Always available
pub mod config;       // Always available

#[cfg(feature = "storage")]
pub mod storage;      // PostgreSQL persistence

#[cfg(feature = "mcp")]
pub mod mcp;          // MCP server (requires storage)
```

The `mcp` feature implies `storage` -- the MCP server needs database access for project management and finding persistence. All feature-gated dev-dependencies are duplicated in `[dev-dependencies]` so tests can compile against all features.

---

## 12. Error Handling

`ScorchError` is the unified error type covering all failure domains:

| Variant | Domain |
|---------|--------|
| `Http { url, source }` | HTTP request failures (wraps `reqwest::Error`) |
| `ToolNotFound { tool }` | External tool not in PATH |
| `ToolFailed { tool, status, stderr }` | Tool exited non-zero |
| `ToolOutputParse { tool, reason }` | Cannot parse tool output |
| `Config(String)` | Configuration errors |
| `InvalidTarget { target, reason }` | Target URL parsing failure |
| `AiAnalysis(String)` | Claude CLI failures |
| `Report(String)` | Report generation errors |
| `Io(io::Error)` | File I/O (via `From`) |
| `Json(serde_json::Error)` | JSON serialization (via `From`) |
| `Database(String)` | PostgreSQL errors |
| `Cancelled { reason }` | Scan interruption (semaphore closed) |

All public functions return `engine::error::Result<T>` (alias for `std::result::Result<T, ScorchError>`). `unwrap()` and `expect()` are denied by clippy lint. `unsafe` code is denied at the crate level.

---

## 13. Additional Subsystems

### Webhook Notifications

Fire-and-forget JSON webhook delivery for scan lifecycle events. Events: `ScanStarted`, `ScanCompleted`, `FindingDiscovered`. Configured via `[[webhooks]]` sections in config.toml with optional event type filtering. Delivery failures are logged but never block scanning.

### Out-of-Band Detection

Wraps `interactsh-client` as a long-running subprocess for blind vulnerability detection. Provides OOB callback URLs for SSRF, XXE, RCE, and blind SQLi payloads. Interactions are correlated back to originating payloads via correlation IDs.

### Scan Schedules

Cron-based recurring scan schedules stored in PostgreSQL. The `croner` crate computes next-run times from cron expressions. Schedules are triggered explicitly via `scorchkit schedule run-due` CLI or `run-due-scans` MCP tool (no daemon).

---

## 14. Key Dependencies

| Crate | Version | Purpose |
|-------|---------|---------|
| `clap` | 4 | CLI argument parsing with derive macros |
| `tokio` | 1 | Async runtime (full features) |
| `reqwest` | 0.12 | HTTP client (rustls-tls, cookies, JSON, multipart) |
| `scraper` | 0.22 | HTML parsing for content analysis |
| `serde` + `serde_json` + `toml` | 1 / 1 / 0.8 | Serialization |
| `thiserror` | 2 | Error type derivation |
| `chrono` | 0.4 | Timestamps (serde support) |
| `indicatif` | 0.17 | Progress bars and spinners |
| `colored` | 3 | Terminal color output |
| `rustls` + `tokio-rustls` + `x509-parser` | 0.23 / 0.26 / 0.16 | TLS inspection and certificate analysis |
| `async-trait` | 0.1 | Async trait support for ScanModule |
| `uuid` | 1 | Scan and entity ID generation (v4) |
| `tracing` + `tracing-subscriber` | 0.1 / 0.3 | Structured logging with env-filter |
| `governor` | 0.8 | Rate limiting |
| `tokio-tungstenite` | 0.26 | WebSocket scanning |
| `base64` | 0.22 | JWT decoding |
| `sqlx` | 0.8 | PostgreSQL async driver (feature-gated: `storage`) |
| `sha2` | 0.10 | Finding fingerprint hashing (feature-gated: `storage`) |
| `croner` | 3 | Cron expression parsing (feature-gated: `storage`) |
| `rmcp` | 1.3 | MCP server framework (feature-gated: `mcp`) |
| `schemars` | 1.0 | JSON Schema generation for MCP tools (feature-gated: `mcp`) |

---

## 15. Design Principles

1. **Modular** -- Adding a new scanner: implement the `ScanModule` trait, register in `register_modules()`. No other files change.
2. **Fail gracefully** -- A module error skips that module, does not abort the scan. Tool not installed? Skip and report. AI failed? Fall back to profile.
3. **No unsafe** -- `unsafe_code` is denied at the lint level.
4. **Zero warnings** -- `clippy::pedantic` and `clippy::nursery` are both enabled. `unwrap_used` and `expect_used` are denied.
5. **Async-first** -- All network I/O and subprocess calls are async via tokio.
6. **Structured output** -- Every finding carries severity, OWASP category, CWE ID, compliance controls, evidence, remediation, and confidence.
7. **Config-driven** -- All behavior is configurable via TOML, with sensible defaults. CLI flags override config.
8. **CLI-first** -- No GUI, no web server (except MCP stdio). Fast terminal workflow.
9. **Feature-gated** -- Optional subsystems (storage, MCP) are compile-time opt-in to keep the default binary lean.
10. **Deterministic dedup** -- Finding fingerprints exclude evidence and timestamps so the same vulnerability across scans deduplicates correctly.
