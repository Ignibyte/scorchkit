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
```

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
