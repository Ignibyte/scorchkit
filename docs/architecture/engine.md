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

### Shared TLS probe helpers (`tls_probe.rs`)

Extracted in WORK-109 so the DAST `scanner::ssl` and Infra `infra::tls_probe::TlsInfraModule` produce identical finding shapes from the same cert-analysis logic. Exports: `CertInfo` (subject, SANs, issuer, not-before / not-after, signature algorithm), `TlsMode` (`Implicit` / `Starttls` / `RdpTls`), `StarttlsProtocol` (Smtp / Imap / Pop3 — each owns its protocol-specific preamble), `probe_tls(host, port, mode)` (connect → optional STARTTLS or RDP X.224 upgrade → rustls handshake → extract peer cert), `parse_certificate(der)`, and `check_certificate(info)` (expired, self-signed, weak signature, subject/SAN mismatch). STARTTLS and RDP-TLS preambles are tested via ephemeral `TcpListener` fixtures that script the wire format (SMTP / IMAP / POP3 for STARTTLS; MS-RDPBCGR X.224 Connection Request / Connection Confirm for RDP-TLS) without needing a real TLS server. The `TlsMode::RdpTls` branch (WORK-148) sends a fixed 38-byte CR packet requesting `PROTOCOL_SSL`; hosts that require CredSSP/NLA respond with `RDP_NEG_FAILURE` and surface as Info findings rather than failing the scan.

### TLS enumeration (`tls_enum.rs`)

Added in WORK-143 alongside `tls_probe`. Where `tls_probe` answers "is the peer cert valid?", `tls_enum` answers "which protocol versions and cipher suites does the server accept?" Exports: `TlsVersionId` (SSLv3 / TLSv1.0 / TLSv1.1 / TLSv1.2 / TLSv1.3 with `wire()`, `label()`, `severity_when_accepted()`, `is_legacy()` helpers), `CipherSuiteId(u16)` IANA wrapper with `name()` + `weakness()` classification, `CipherWeakness` (Ok / Legacy / Weak / Critical with `severity()` mapping), `ProbeOutcome` (Accepted / Rejected / Unknown), plus `probe_tls_version`, `probe_tls_cipher`, `enumerate_tls_versions`, and `enumerate_weak_ciphers`. Implementation splits by rustls capability: modern versions (TLS1.2 / TLS1.3) go through a rustls handshake with a deliberately permissive cert verifier (`NoCertVerifier`), legacy versions (SSLv3 / TLS1.0 / TLS1.1) and all cipher-acceptance probes use a hand-crafted raw-socket ClientHello whose server response is classified by inspecting the first record's content_type byte. rustls 0.23 refuses to speak pre-TLS1.2 and does not implement weak cipher suites (RC4, 3DES, EXPORT, NULL, anon), so the raw-socket path is the only viable route without adding a new TLS stack dependency. Cipher catalog is a ~38-entry static table keyed on IANA IDs, covering every known Critical / Weak / Legacy suite plus a small set of Ok baselines so reports can confirm modern AEAD is also offered. TLS1.3 cipher enumeration is deliberately out of scope (RFC 8446 defines only 5 AEAD suites, all modern).

### API spec shared-data (`api_spec.rs`)

WORK-108's bridge between API-discovery producers (`tools::vespasian`) and six downstream scanners. `ApiEndpoint { method, url, parameters }` and `ApiSpec { title, endpoints }` are the lowest-common-denominator types that capture what every consumer needs — callers translate from OpenAPI 3.0 / GraphQL SDL / WSDL into `ApiSpec` so consumers never see vendor formats. `publish_api_spec(&ctx.shared_data, &spec)` and `read_api_spec(&ctx.shared_data) -> Option<ApiSpec>` are the helpers; `SHARED_KEY_API_SPEC` holds exactly one publication per scan (last writer wins). Wired consumers in v2.1: `scanner::injection`, `scanner::csrf`, `scanner::idor`, `scanner::graphql`, `scanner::auth`, `scanner::ratelimit`. See [api-spec-shared-data.md](api-spec-shared-data.md) for the full producer / consumer contract.

### Service fingerprints (`service_fingerprint.rs`)

`ServiceFingerprint { port, protocol, service_name, product, version, cpe }` is the shared data type for service detection. `parse_nmap_xml_fingerprints(xml)` is the pure parser both the DAST `tools::NmapModule` and the infra `infra::NmapModule` call; the DAST wrapper layers severity classification and outdated-version checks on top, while the infra wrapper emits Info findings and publishes `Vec<ServiceFingerprint>` to `shared_data` under the `SHARED_KEY_FINGERPRINTS` constant for downstream CVE correlation. `build_cpe(vendor, product, version)` produces CPE 2.3 URIs. `publish_fingerprints` / `read_fingerprints` helpers encapsulate the JSON encoding required to round-trip structured data through `SharedData`'s `Vec<String>` store.

## Cloud module family (v2.2 foundation)

Fourth scanning family, landed in WORK-150. Parallel to DAST (`ScanModule`), SAST (`CodeModule`), and Infra (`InfraModule`) but operates on cloud control planes — AWS accounts, GCP projects, Azure subscriptions, and Kubernetes cluster contexts — via the new `CloudModule` trait in `src/engine/cloud_module.rs`. Gated on the new `cloud` Cargo feature.

**Two-axis classification.** Unlike `InfraCategory` (single axis — protocol implies stack), cloud posture splits across two orthogonal enums:

- **`CloudCategory`** (exactly one per module) — `Iam` / `Storage` / `Network` / `Compute` / `Kubernetes` / `Compliance` (cross-cutting benchmarks)
- **`CloudProvider`** (zero or more per module) — `Aws` / `Gcp` / `Azure` / `Kubernetes`

A cross-cloud "publicly-readable object storage" module is `CloudCategory::Storage` with `providers() == &[Aws, Gcp, Azure]`.

**`CloudTarget` — prefix-dispatched parser.** `CloudTarget::parse` accepts `aws:123456789012` / `gcp:my-project` / `azure:<sub-guid>` / `k8s:<context>` / `all`. Unlike `InfraTarget::parse`'s shape inference, explicit prefixes are required because cloud IDs lack distinguishing syntactic fingerprints (AWS account numerics collide with port numbers, GCP project IDs are hostname-shaped, Azure GUIDs are ambiguous).

**`CloudContext` — deliberate absence of `http_client`.** Unlike `InfraContext`, `CloudContext` does **not** carry a `reqwest::Client`. Cloud modules call provider SDKs (which manage their own HTTP clients with request signing) or tool-wrapper subprocesses (Prowler / Scoutsuite / Kubescape), never arbitrary `reqwest` calls. Future modules needing HTTP construct clients locally.

**`CloudCredentials`** — WORK-146 `NetworkCredentials` pattern applied to cloud: hand-written `Debug` (never `derive`), env-var precedence via `SCORCHKIT_*` variables (`SCORCHKIT_AWS_PROFILE`, `SCORCHKIT_KUBE_CONTEXT`, …), env-wins-non-empty semantics. Eight `Option<String>` fields today — `aws_profile` / `aws_role_arn` / `aws_region` / `gcp_service_account_path` / `gcp_project_id` / `azure_subscription_id` / `azure_tenant_id` / `kube_context` — all identifiers that SDKs use to locate secrets elsewhere on disk. Hand-written `Debug` is mandatory regardless so future direct-bearer fields (e.g., `aws_secret_access_key` in WORK-151+) are redacted by construction.

**`CloudOrchestrator`** — structural copy of `InfraOrchestrator` (~90% identical). Same lifecycle events, same semaphore-bounded concurrency, same audit-log wiring, same `ScanResult` return. Empty-registry contract: `cloud::register_modules()` returns `vec![]` at WORK-150 and the orchestrator handles that cleanly — `ScanStarted` + `ScanCompleted` still fire with zero findings. Concrete modules land in WORK-151 (Prowler), WORK-152 (Scoutsuite), WORK-153 (Kubescape), WORK-154 (finding normalization). Refactor to a generic `Orchestrator<M, C, T>` is deferred to a later pipeline — the concrete orchestrators remain readable and shipped.

**Synthetic `cloud://` URL scheme.** `Target::from_cloud(raw)` wraps cloud-target strings in `cloud://...` so reporting / storage / AI layers consume cloud scans identically to DAST / SAST / Infra. Percent-encoding handles the `:` separator. Full operator docs in `docs/architecture/cloud.md`.

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
