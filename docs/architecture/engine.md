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
