# ScorchKit Plugin SDK

ScorchKit exposes its module traits as a public Rust SDK. Third-party
developers can write native Rust scan modules that plug into the same
orchestrator and reporting pipeline as built-in modules.

## Quick Start

Add ScorchKit to your `Cargo.toml`:

```toml
[dependencies]
scorchkit = "1.0"
async-trait = "0.1"
```

Implement `ScanModule` or `CodeModule`:

```rust
use async_trait::async_trait;
use scorchkit::prelude::*;

pub struct MyScanner;

#[async_trait]
impl ScanModule for MyScanner {
    fn name(&self) -> &'static str { "My Custom Scanner" }
    fn id(&self) -> &'static str { "my-scanner" }
    fn category(&self) -> ModuleCategory { ModuleCategory::Scanner }
    fn description(&self) -> &'static str { "What this module does" }

    async fn run(&self, ctx: &ScanContext) -> Result<Vec<Finding>> {
        // Your scan logic here.
        // Use ctx.http_client for HTTP requests.
        // Return findings as Vec<Finding>.
        Ok(vec![])
    }
}
```

## Module Types

ScorchKit has two module traits:

| Trait | Use For | Context | Examples |
|-------|---------|---------|----------|
| `ScanModule` | DAST (runtime web testing) | `ScanContext` (URL + HTTP client) | XSS, SQL injection, headers |
| `CodeModule` | SAST (static code analysis) | `CodeContext` (filesystem path) | Secret detection, dep audit |

Pick the trait that matches your scan target. A URL-based security check
is `ScanModule`. A code-level analyzer is `CodeModule`.

## The Finding Builder

Every module produces `Vec<Finding>`. Use the fluent builder:

```rust
use scorchkit::prelude::*;

let finding = Finding::new(
    "my-scanner",                           // module_id
    Severity::High,                         // severity
    "Vulnerability Title",                  // title
    "Description of what was found",        // description
    "https://example.com/endpoint",         // affected_target (URL or file:line)
)
.with_evidence("Raw request/response or proof")
.with_remediation("Step-by-step fix instructions")
.with_owasp("A03:2021 Injection")
.with_cwe(89)
.with_confidence(0.85);                     // 0.0-1.0, default 0.5
```

### Confidence Values

Confidence indicates false-positive likelihood:

| Range | Meaning |
|-------|---------|
| 0.9-1.0 | Definitive — proof-of-concept exploit or deterministic check |
| 0.7-0.89 | High — strong signal, minor chance of FP |
| 0.5-0.69 | Medium — pattern match, could be FP depending on context |
| 0.3-0.49 | Low — heuristic or speculative |

Users filter by confidence with `--min-confidence`.

## ScanContext (DAST modules)

```rust
pub struct ScanContext {
    pub target: Target,                 // URL, domain, port, TLS flag
    pub config: Arc<AppConfig>,         // Full config (scan, auth, tools)
    pub http_client: reqwest::Client,   // Preconfigured with auth/proxy/TLS
    pub shared_data: Arc<SharedData>,   // Inter-module data sharing
}
```

**Always use `ctx.http_client`** — it's configured with auth headers,
proxy routing, cookie jar, timeouts, and TLS settings from user config.
Building your own client defeats those settings.

### Inter-Module Data Sharing

Modules can publish and consume shared data via `ctx.shared_data`:

```rust
// Publish (typically in recon modules)
ctx.shared_data.push(scorchkit::engine::shared_data::URLS, "https://example.com/api");

// Consume (typically in scanner modules)
let urls = ctx.shared_data.get(scorchkit::engine::shared_data::URLS);
```

Standard keys: `URLS`, `FORMS`, `PARAMS`, `TECHNOLOGIES`, `SUBDOMAINS`.

## CodeContext (SAST modules)

```rust
pub struct CodeContext {
    pub path: PathBuf,                  // Root directory to scan
    pub language: Option<String>,       // Auto-detected from manifests
    pub manifests: Vec<PathBuf>,        // Discovered Cargo.toml, package.json, etc.
    pub config: Arc<AppConfig>,         // Full config
    pub shared_data: Arc<SharedData>,   // Same as ScanContext
}
```

### Language Filtering

Return supported languages from `languages()`:

```rust
fn languages(&self) -> &[&str] {
    &["python", "javascript"]  // Only runs on Python/JS projects
}

// Return empty to run on any codebase:
fn languages(&self) -> &[&str] { &[] }
```

The orchestrator uses this for automatic filtering — a Python-only
scanner won't run on a Go project.

## Error Handling

Return `scorchkit::engine::error::Result<Vec<Finding>>` (re-exported as
`Result` in the prelude):

```rust
async fn run(&self, ctx: &ScanContext) -> Result<Vec<Finding>> {
    let response = ctx.http_client
        .get(ctx.target.url.as_str())
        .send()
        .await
        .map_err(|e| ScorchError::Config(format!("request failed: {e}")))?;
    // ...
}
```

Module failures are non-fatal — a single module erroring won't abort
the whole scan. But return meaningful errors so users can diagnose issues.

## Registering Your Module

Since ScorchKit doesn't yet load native Rust plugins dynamically, the
typical integration is to **build your own binary** that wraps ScorchKit:

```rust
use scorchkit::prelude::*;
use scorchkit::runner::orchestrator::Orchestrator;
use std::sync::Arc;

#[tokio::main]
async fn main() -> Result<()> {
    let config = Arc::new(AppConfig::default());
    let http_client = scorchkit::facade::build_http_client(&config)?;
    let target = Target::parse("https://example.com")?;
    let ctx = ScanContext::new(target, config, http_client);

    let mut orchestrator = Orchestrator::new(ctx);
    orchestrator.register_default_modules();

    // Add your custom module alongside the built-ins:
    // (requires accessing the modules vec directly — see src/runner/orchestrator.rs)

    let result = orchestrator.run(false).await?;
    println!("Found {} findings", result.findings.len());
    Ok(())
}
```

For the simpler **TOML-based plugin system** (no Rust compilation required),
see `src/runner/plugin.rs` — it loads scanner definitions from `.toml`
files that wrap external CLI tools.

## Testing Your Module

The Finding builder and module trait are fully testable without a real
HTTP server:

```rust
#[test]
fn test_build_finding() {
    let finding = Finding::new(
        "my-module",
        Severity::Medium,
        "Test",
        "Description",
        "https://example.com",
    )
    .with_confidence(0.8);

    assert_eq!(finding.module_id, "my-module");
}
```

For integration testing with HTTP, use `wiremock` or `mockito` crates.

## Complete Examples

See the `examples/` directory in the ScorchKit repository:

- `examples/custom_scanner/` — complete DAST `ScanModule` implementation
- `examples/custom_code_scanner/` — complete SAST `CodeModule` implementation

Both examples compile as standalone crates that depend on the main
`scorchkit` crate via path dependency.

## Key Types Reference

All core types are re-exported from `scorchkit::prelude`:

| Type | Purpose |
|------|---------|
| `Finding` | Single security finding with builder methods |
| `Severity` | `Critical`, `High`, `Medium`, `Low`, `Info` |
| `Target` | Parsed URL/domain target for DAST |
| `ScanResult` | Complete scan output (findings + metadata) |
| `ScanModule` | DAST module trait |
| `CodeModule` | SAST module trait |
| `ModuleCategory` | `Recon` or `Scanner` (DAST categorization) |
| `CodeCategory` | `Sast`, `Sca`, `Secrets`, `Iac`, `Container` |
| `ScanContext` | DAST execution context |
| `CodeContext` | SAST execution context |
| `AppConfig` | User configuration |
| `Result<T>` | `std::result::Result<T, ScorchError>` alias |
| `ScorchError` | Error enum with typed variants |
| `Engine` | High-level facade for library consumers |

## Design Principles

When writing a module:

1. **One module, one concern.** Don't try to do auth *and* injection
   in one module — split them.
2. **Deterministic IDs.** The `id()` string is stable and user-facing
   (appears in CLI flags, config, findings). Pick something short and
   descriptive: `my-auth-check`, not `MyAuthChecker_v2`.
3. **Graceful failure.** A missing optional input shouldn't error —
   return empty `Vec<Finding>`. Reserve errors for real failures
   (network down, malformed config).
4. **Explicit confidence.** Always call `.with_confidence(...)`. The
   default is 0.5 which is rarely accurate.
5. **Use `ctx.http_client`.** Never build your own reqwest client —
   you'll bypass user proxy/auth/TLS settings.
6. **Test pure functions.** Extract parsing/analysis logic into pure
   functions and test those directly. Mock HTTP only when necessary.
