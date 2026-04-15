# Engine

The `engine` module (`src/engine/`) contains all core types that the rest of the system depends on. It was named `engine` rather than `core` to avoid shadowing Rust's `std::core`.

## Module Map

```
engine/
  mod.rs             Module declarations
  error.rs           ScorchError enum + Result type alias
  severity.rs        Severity enum (Info → Critical)
  target.rs          Target struct (URL/domain parsing)
  finding.rs         Finding struct (scan output)
  module_trait.rs    ScanModule trait + ModuleCategory enum
  scan_context.rs    ScanContext (shared state for modules)
  scan_result.rs     ScanResult + ScanSummary (aggregated output)
  compliance.rs      OWASP/CWE to NIST/PCI-DSS/SOC2/HIPAA mapping
  evidence.rs        HttpEvidence struct for request/response capture
  scope.rs           ScopeRule enum for scope management
  oob.rs             Out-of-band callback infrastructure (Interactsh)
  events.rs          Event bus — ScanEvent enum, EventBus, EventHandler trait
  hook_runner.rs     Script-based lifecycle hooks + HookEventHandler adapter
```

## Event Bus v2 (`events.rs`)

In-process pub/sub for scan lifecycle events, wrapping `tokio::sync::broadcast`:

- **`ScanEvent`** — 7 owned (no-lifetime, `Clone`) variants: `ScanStarted`, `ModuleStarted`, `ModuleCompleted`, `ModuleSkipped`, `ModuleError`, `FindingProduced` (with `Box<Finding>`), `ScanCompleted`.
- **`EventBus`** — cheaply-cloneable wrapper over `broadcast::Sender<ScanEvent>`. Fire-and-forget `publish()` (send errors only when there are zero subscribers; logged at `debug`). `subscribe()` hands out receivers; `subscriber_count()` for diagnostics. Default capacity 256.
- **`EventHandler`** — async trait (`Send + Sync`) with `handle(&self, event) -> Result<(), String>`. Handler errors are logged, not propagated — observability must never abort a scan.
- **`subscribe_handler(bus, handler)`** — spawns a tokio task that drives the handler with every event until the bus is dropped (receiver sees `RecvError::Closed`). Lagged receivers log and continue.

`EventBus` is a field on both `ScanContext.events` and `CodeContext.events` so modules may publish custom events. The orchestrators (`Orchestrator::run()`, `run_with_checkpoint()`, `run_phased()`, `run_module_batch()`; `CodeOrchestrator::run()`) publish lifecycle events at every relevant point.

### Custom module events (v2b.1)

`ScanEvent::Custom { kind: String, data: serde_json::Value }` lets modules emit domain-specific events without expanding the core lifecycle variant set. Kinds follow a dotted-namespace convention (e.g. `"crawler.depth-reached"`, `"waf.detected"`) — documented but not enforced. Typed payloads round-trip via `serde_json::to_value` / `serde_json::from_value`.

`subscribe_filtered(bus, handler, predicate)` wraps `subscribe_handler` with a predicate check before handler dispatch. The filter runs on the subscriber's task (broadcast still delivers every event to every subscriber; the filter just chooses to ignore non-matches). Generic over `F: Fn(&ScanEvent) -> bool + Send + Sync + 'static` for ergonomic closure use with zero explicit boxing.

`HookEventHandler` ignores `ScanEvent::Custom` — there's no standard mapping from an arbitrary kind string to the three hook points. Users who want script dispatch for custom events can write a native `EventHandler` directly.

### Built-in audit log (`AuditLogHandler`)

`src/engine/audit_log.rs` provides the first production subscriber of the event bus — a file-based JSONL sink enabled via `[audit_log]` in `scorchkit.toml`.

- `AuditLogHandler::new(&path)` opens the file in append+create mode (returns `ScorchError::Io` on failure).
- `impl EventHandler` serializes each `ScanEvent` with `serde_json::to_string` and appends `{line}\n`; flushes after every write.
- I/O errors are logged at `warn` and swallowed — audit logging is best-effort observability and must never abort a scan.
- `subscribe_audit_log_if_enabled(&config.audit_log, &ctx.events)` is the helper both orchestrators call at the top of `run()` (before the first publish) to wire the handler when config enables it.

`ScanEvent` derives `Serialize` to support JSON emission. Variant and field names are part of the on-the-wire JSONL format: renaming either is a breaking change for downstream consumers. The default externally-tagged representation means each line is a single-key object like `{"ScanStarted": {"scan_id": "...", "target": "..."}}`.

## Infra module family (v2.0 foundation)

`src/engine/infra_module.rs` introduces the third module family alongside `ScanModule` (DAST) and `CodeModule` (SAST). All infra code is feature-gated behind `infra = ["dep:ipnet"]` and absent from the default build.

- **`InfraModule`** — async trait with `name`/`id`/`category`/`description`/`run`/`requires_external_tool`/`required_tool`/`protocols` methods, mirroring `ScanModule`.
- **`InfraCategory`** — five variants in v1: `PortScan`, `Fingerprint`, `CveMatch`, `TlsInfra`, `Dns`. WORK-104 will add `NetworkAuth` and `ServiceEnum`.
- **`InfraTarget`** (`src/engine/infra_target.rs`) — sum type with `Ip(IpAddr)`, `Cidr(ipnet::IpNet)`, `Host(String)`, `Endpoint { host, port }`, and `Multi(Vec<Self>)` variants. `parse(&str)` accepts CIDR, IP, host, host:port, and bracketed IPv6 endpoint forms. `iter_ips()` flattens the target into individual addresses (CIDR via `IpNet::hosts`, host returns empty pending DNS resolution in WORK-102).
- **`InfraContext`** (`src/engine/infra_context.rs`) — same shape as `ScanContext`/`CodeContext`: target, config, HTTP client, shared data, and the event bus. Network credentials field comes in WORK-104.
- **`InfraOrchestrator`** (`src/runner/infra_orchestrator.rs`) — mirrors `Orchestrator`/`CodeOrchestrator` exactly: same `ScanEvent` lifecycle sequence, same `subscribe_audit_log_if_enabled` wire-up, same semaphore-bounded concurrency. Returns the existing `ScanResult` type (target reuses `Target::from_infra` to wrap the infra target string in a synthetic `infra://` URL — same trick `from_path` uses for SAST).
- **`TcpProbeModule`** (`src/infra/tcp_probe.rs`) — the v1 demonstration module. Privilege-free TCP-connect probe against a configurable port list (default: 22, 80, 443, 3306, 5432, 6379, 8080, 8443) with bounded timeout. Emits one Info Finding per open port. Real port scanning (SYN/XMAS) lands in WORK-102's nmap migration.
- **CLI:** `scorchkit infra <target> [--profile quick|standard] [--modules a,b,c] [--skip x,y]` (gated).
- **Facade:** `Engine::infra_scan(target: &str)` (gated).

The roadmap continues with WORK-103 (OSV CVE matcher), WORK-104 (authenticated network scanning), WORK-105 (unified `assess` command composing DAST+SAST+Infra), WORK-106 (storage migration + MCP tools).

### CVE correlation (`cve.rs` + `infra/cve_match.rs`)

`CveRecord { id, cvss_score, severity, description, references, cpe }` is the unified shape for CVE data across the codebase (findings, storage, reporting). `CveLookup` is an async trait (`Send + Sync`) with a single `query(cpe) -> Result<Vec<CveRecord>>` method — backends are free to hit NVD, OSV, a local database, or return test fixtures. `severity_from_cvss` maps a CVSS v3.x base score onto `Severity` using standard bands.

`infra::CveMatchModule` is the consumer side of the WORK-102 fingerprint pipeline. It reads fingerprints via `read_fingerprints`, iterates those with a `cpe` set, queries the injected lookup sequentially, and emits one `Finding` per matched CVE with the CVE ID + CVSS score in the title and evidence. Per-fingerprint query errors are logged at `warn` and skipped so a single backend hiccup doesn't abort the scan.

`CveMatchModule::new(lookup: Box<dyn CveLookup>)` takes its backend by injection — it's intentionally absent from `infra::register_modules()`. The fixture-backed `infra::MockCveLookup` exercises the module in tests. Two production backends ship behind the same trait: `infra::cve_nvd::NvdCveLookup` (WORK-103b) for system-software CPEs and `infra::cve_osv::OsvCveLookup` (WORK-103c) for language-package CPEs. Backend selection is config-driven: `[cve] backend = "disabled" | "mock" | "nvd" | "osv"` plus a `[cve.nvd]` or `[cve.osv]` sub-block. `infra::cve_lookup::build_cve_lookup(&AppConfig)` is the factory; `Engine::infra_scan` (which `full_assessment` calls) consults it and appends `CveMatchModule` automatically when a backend is configured. Both backends own their own `reqwest::Client` (separate from the scan client so pen-test proxy / insecure-TLS settings never leak into vendor calls), wrap a `governor::RateLimiter` (NVD: 5/30s anonymous or 50/30s with key; OSV: conservative 10 RPS under their ~25 QPS fair-use cap), and consult a sha256-keyed file-system TTL cache (`infra::cve_cache::FsCache`, with negative caching) under per-backend cache directories (`scorchkit/cve/` for NVD, `scorchkit/cve-osv/` for OSV) so flushing one doesn't affect the other. OSV's package-coordinate API requires CPE → ecosystem translation; the pure `infra::cpe_purl::cpe_to_package(cpe)` carries an embedded ≥30-entry static mapping table covering the highest-value language-ecosystem CPEs (npm, PyPI, Maven, Go, crates.io, RubyGems, NuGet, Packagist) and returns `None` for unmapped CPEs (system software lives in NVD, not OSV). OSV severities arrive as CVSS vector strings; the new `engine::cve::cvss_v3_base_score(vector)` is a faithful in-process implementation of the [CVSS v3.1 base-score formula](https://www.first.org/cvss/v3.1/specification-document) reusable by any future vector-surfacing backend. See `docs/modules/cve-nvd.md` and `docs/modules/cve-osv.md` for operator-facing config references.

### Service fingerprints (`service_fingerprint.rs`)

`ServiceFingerprint { port, protocol, service_name, product, version, cpe }` is the shared data type for service detection. `parse_nmap_xml_fingerprints(xml)` is the pure parser both the DAST `tools::NmapModule` and the infra `infra::NmapModule` call; the DAST wrapper layers severity classification and outdated-version checks on top, while the infra wrapper emits Info findings and publishes `Vec<ServiceFingerprint>` to `shared_data` under the `SHARED_KEY_FINGERPRINTS` constant for downstream CVE correlation. `build_cpe(vendor, product, version)` produces CPE 2.3 URIs. `publish_fingerprints` / `read_fingerprints` helpers encapsulate the JSON encoding required to round-trip structured data through `SharedData`'s `Vec<String>` store.

## Hook adapter — `HookEventHandler` (`hook_runner.rs`)

`HookEventHandler` bridges the event bus to the existing script-based hook system. It subscribes to the event stream and maps events to the three `HookPoint` script invocations:

- `ScanEvent::ScanStarted` → `HookPoint::PreScan`
- `ScanEvent::FindingProduced` → buffered per `(scan_id, module_id)` in an internal `Mutex<HashMap>`
- `ScanEvent::ModuleCompleted` → `HookPoint::PostModule` (buffer drained, full findings array handed to the script)
- `ScanEvent::ScanCompleted` → `HookPoint::PostScan`

The adapter runs hooks for observable side effects (logging, notifications, exports). It does **not** feed modifications back into the scan result — publishing is fire-and-forget. Post-module finding modification remains handled by the synchronous `HookRunner::execute()` call in `Orchestrator::run()`. The two systems coexist: the orchestrator still invokes `HookRunner` directly; `HookEventHandler` is an additive opt-in for event-driven subscribers.

## ScorchError (`error.rs`)

Unified error type for all of ScorchKit. Uses `thiserror` derive. Every fallible function in the codebase returns `engine::error::Result<T>`.

```rust
pub enum ScorchError {
    Http { url: String, source: reqwest::Error },
    ToolNotFound { tool: String },
    ToolFailed { tool: String, status: i32, stderr: String },
    ToolOutputParse { tool: String, reason: String },
    Config(String),
    InvalidTarget { target: String, reason: String },
    AiAnalysis(String),
    Report(String),
    Io(io::Error),          // #[from]
    Json(serde_json::Error), // #[from]
    Cancelled { reason: String },
}

pub type Result<T> = std::result::Result<T, ScorchError>;
```

**Variant usage:**
- `Http` - network/TLS/DNS failures during HTTP requests
- `ToolNotFound` - external tool binary not in PATH
- `ToolFailed` - external tool exited with non-zero status
- `ToolOutputParse` - couldn't parse tool's stdout into findings
- `Config` - TOML parse error, missing field, invalid value
- `InvalidTarget` - user-provided target can't be parsed as URL/domain
- `AiAnalysis` - Claude CLI subprocess failure
- `Report` - report generation/serialization failure
- `Io` / `Json` - auto-converted via `#[from]`
- `Cancelled` - scan timeout or user interrupt

## Severity (`severity.rs`)

```rust
pub enum Severity {
    Info,      // Informational, no direct risk
    Low,       // Minor issue, low exploitation likelihood
    Medium,    // Moderate risk, should be addressed
    High,      // Significant risk, prioritize remediation
    Critical,  // Immediate risk, must be fixed now
}
```

Derives `PartialOrd, Ord` so findings can be sorted by severity (Critical > High > Medium > Low > Info).

**Methods:**
- `colored_str(self) -> String` - Returns a colored string for terminal output (blue/green/yellow/red/red-on-white)
- `Display` impl - lowercase string (`"info"`, `"low"`, etc.)

Serializes as lowercase strings in JSON via `#[serde(rename_all = "lowercase")]`.

## Target (`target.rs`)

Parsed from user input. Accepts full URLs (`https://example.com/path`) or bare domains (`example.com`). Bare domains default to HTTPS on port 443.

```rust
pub struct Target {
    pub raw: String,           // Original user input
    pub url: Url,              // Parsed url::Url
    pub domain: Option<String>, // Extracted hostname
    pub port: u16,             // From URL or default (443/80)
    pub is_https: bool,        // Scheme check
}
```

**Methods:**
- `Target::parse(input: &str) -> Result<Self>` - Main constructor. Prepends `https://` if no scheme provided.
- `base_url(&self) -> String` - Returns `scheme://host[:port]` (port omitted if default)
- `Display` impl - prints the full parsed URL

**Validation:** Returns `ScorchError::InvalidTarget` if the input can't be parsed or has no host.

## Finding (`finding.rs`)

The universal output type for all scan modules. Every security issue, informational note, or detection is represented as a `Finding`.

```rust
pub struct Finding {
    pub module_id: String,           // e.g., "headers"
    pub severity: Severity,
    pub title: String,               // e.g., "Missing HSTS Header"
    pub description: String,         // Detailed explanation
    pub affected_target: String,     // URL, parameter, header, etc.
    pub evidence: Option<String>,    // Raw response data proving the finding
    pub remediation: Option<String>, // How to fix it
    pub owasp_category: Option<String>, // e.g., "A05:2021 Security Misconfiguration"
    pub cwe_id: Option<u32>,         // e.g., 319
    pub compliance: Option<Vec<String>>, // NIST/PCI-DSS/SOC2/HIPAA controls
    pub http_evidence: Option<HttpEvidence>, // Full request/response PoC
    pub timestamp: DateTime<Utc>,
}
```

**Constructor + Builder pattern:**
```rust
Finding::new("headers", Severity::High, "Missing HSTS", "description...", "https://target.com")
    .with_evidence("Header value: ...")
    .with_remediation("Add Strict-Transport-Security header")
    .with_owasp("A05:2021 Security Misconfiguration")
    .with_cwe(319)
    .with_compliance(vec!["NIST SC-8".to_string(), "PCI-DSS 4.1".to_string()])
    .with_http_evidence(HttpEvidence::new("GET", "https://target.com", 200)
        .with_response_body("<html>...</html>"))
```

Optional fields skip serialization when `None` (via `#[serde(skip_serializing_if)]`).

## ScanModule Trait (`module_trait.rs`)

The core abstraction. See [modules.md](modules.md) for the full contract and implementation guide.

```rust
pub enum ModuleCategory { Recon, Scanner }

#[async_trait]
pub trait ScanModule: Send + Sync {
    fn name(&self) -> &str;
    fn id(&self) -> &str;
    fn category(&self) -> ModuleCategory;
    fn description(&self) -> &str;
    async fn run(&self, ctx: &ScanContext) -> Result<Vec<Finding>>;
    fn requires_external_tool(&self) -> bool { false }
    fn required_tool(&self) -> Option<&str> { None }
}
```

## ScanContext (`scan_context.rs`)

Shared state passed to every module during a scan. Cloneable (Arc-backed config).

```rust
pub struct ScanContext {
    pub target: Target,
    pub config: Arc<AppConfig>,
    pub http_client: reqwest::Client,  // Pooled, pre-configured
}
```

The `http_client` is built once with the configured User-Agent, redirect policy, and TLS settings, then shared across all modules.

## ScanResult (`scan_result.rs`)

Aggregated output from a complete scan.

```rust
pub struct ScanResult {
    pub scan_id: String,                      // UUID v4
    pub target: Target,
    pub started_at: DateTime<Utc>,
    pub completed_at: DateTime<Utc>,
    pub findings: Vec<Finding>,               // Sorted by severity
    pub modules_run: Vec<String>,             // Module IDs that executed
    pub modules_skipped: Vec<(String, String)>, // (module_id, reason)
    pub summary: ScanSummary,
}

pub struct ScanSummary {
    pub total_findings: usize,
    pub critical: usize,
    pub high: usize,
    pub medium: usize,
    pub low: usize,
    pub info: usize,
}
```

`ScanSummary::from_findings()` computes counts automatically. `ScanResult::new()` sets `completed_at` to now and computes the summary.

## Compliance Mapping (`compliance.rs`)

Maps OWASP Top 10 and CWE identifiers to compliance framework controls across four frameworks:

- **NIST 800-53** (e.g., AC-3, SI-10, SC-8)
- **PCI-DSS 4.0** (e.g., 6.2.4, 8.2, 4.1)
- **SOC2 TSC** (e.g., CC6.1, CC7.1)
- **HIPAA** (e.g., 164.312(a)(1), 164.312(d))

### Functions

```rust
/// Look up controls for an OWASP category (e.g., "A01:2021 Broken Access Control").
pub fn compliance_for_owasp(owasp_id: &str) -> Vec<&'static str>

/// Look up controls for a CWE ID (e.g., 79 for XSS).
pub fn compliance_for_cwe(cwe_id: u32) -> Vec<&'static str>
```

All ten OWASP A01-A10 categories are mapped. Common CWEs (79, 89, 200, 287, 311, 319, 352, 521, 522, 601, 798, 918, 1104) have explicit mappings. Unknown identifiers return empty vec.

Used by the `Finding` builder's `.with_compliance()` method. Modules can auto-populate compliance by looking up their OWASP/CWE references.

## HttpEvidence (`evidence.rs`)

Captures full HTTP request/response pairs for attaching to findings as proof-of-concept evidence.

```rust
pub struct HttpEvidence {
    pub method: String,
    pub url: String,
    pub request_headers: HashMap<String, String>,
    pub request_body: Option<String>,
    pub status_code: u16,
    pub response_headers: HashMap<String, String>,
    pub response_body: Option<String>,    // Truncated to 10KB max
    pub truncated: bool,
}
```

**Builder pattern:**
```rust
HttpEvidence::new("GET", "https://example.com/xss?q=<script>", 200)
    .with_request_headers(headers)
    .with_request_body("POST body")
    .with_response_headers(resp_headers)
    .with_response_body("<html>...</html>")
```

Response bodies exceeding 10KB are automatically truncated with the `truncated` flag set to `true`. Empty maps and `None` fields are skipped during JSON serialization.

Attached to findings via `Finding::with_http_evidence(evidence)`.

## Scope Management (`scope.rs`)

Provides structured scope rules for controlling which targets are in scope for scanning.

```rust
pub enum ScopeRule {
    Exact(String),                    // "example.com"
    Wildcard(String),                 // "*.example.com"
    Cidr { network: u32, mask: u32 }, // "192.168.1.0/24"
}
```

### Functions

```rust
/// Parse a scope rule string, auto-detecting the type.
/// - "*.example.com" → Wildcard
/// - "192.168.1.0/24" → Cidr
/// - Everything else → Exact
ScopeRule::parse(input: &str) -> Option<Self>

/// Check if a host matches this rule.
ScopeRule::matches(&self, host: &str) -> bool

/// Check if a URL's host is in scope. Empty rules = everything in scope.
pub fn is_in_scope(url: &str, rules: &[ScopeRule]) -> bool
```

Wildcard matching requires a dot separator (e.g., `*.example.com` matches `sub.example.com` but not `example.com`). CIDR matching parses the host as an IPv4 address and applies the subnet mask. Non-IP hosts never match CIDR rules.
