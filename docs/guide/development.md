# ScorchKit Development Guide

This guide covers how to extend ScorchKit with new modules, understand its
architecture, and meet the project's quality standards.

## Table of Contents

1. [Architecture Overview](#architecture-overview)
2. [The ScanModule Trait](#the-scanmodule-trait)
3. [Adding a New Scanner Module](#adding-a-new-scanner-module)
4. [Adding a New Recon Module](#adding-a-new-recon-module)
5. [Adding a New Tool Wrapper](#adding-a-new-tool-wrapper)
6. [Finding Builder Pattern](#finding-builder-pattern)
7. [Inter-Module Communication with SharedData](#inter-module-communication-with-shareddata)
8. [Testing Patterns](#testing-patterns)
9. [Quality Standards](#quality-standards)
10. [Plugin System](#plugin-system)
11. [Adding CLI Commands and Flags](#adding-cli-commands-and-flags)

---

## Architecture Overview

ScorchKit is organized around a module system. Every security check, whether
it is a built-in analysis or a wrapper around an external tool, implements the
same `ScanModule` trait. The orchestrator runs modules concurrently via a
tokio semaphore and collects their `Finding` results.

```
src/
  engine/          Core types: Target, Finding, Severity, ScanModule trait,
                   ScanContext, ScorchError, SharedData
  recon/           Reconnaissance modules (headers, tech, crawler, dns, ...)
  scanner/         Vulnerability scanner modules (xss, csrf, injection, ...)
  tools/           External tool wrappers (nmap, nuclei, sqlmap, ...)
  runner/          Orchestrator, subprocess management, plugin loader
  cli/             Clap CLI definition, command dispatch
  config/          TOML configuration loading
  report/          Output formats (terminal, json, html, sarif)
  ai/              Claude AI integration for analysis
```

Key types and their locations:

| Type | File | Purpose |
|------|------|---------|
| `ScanModule` | `src/engine/module_trait.rs` | Trait every module implements |
| `ScanContext` | `src/engine/scan_context.rs` | Shared context passed to modules |
| `Finding` | `src/engine/finding.rs` | A single vulnerability or observation |
| `Severity` | `src/engine/severity.rs` | Info, Low, Medium, High, Critical |
| `SharedData` | `src/engine/shared_data.rs` | Inter-module data passing |
| `Target` | `src/engine/target.rs` | Parsed scan target (URL, domain, port) |
| `ScorchError` | `src/engine/error.rs` | Unified error type via thiserror |
| `HttpEvidence` | `src/engine/evidence.rs` | HTTP request/response capture |

---

## The ScanModule Trait

Every module implements this trait, defined in `src/engine/module_trait.rs`:

```rust
#[async_trait]
pub trait ScanModule: Send + Sync {
    /// Human-readable name for display and reporting.
    fn name(&self) -> &str;

    /// Short identifier used in CLI flags and config keys.
    fn id(&self) -> &str;

    /// Category this module belongs to.
    fn category(&self) -> ModuleCategory;

    /// Brief description of what this module checks.
    fn description(&self) -> &str;

    /// Run the scan against the target in `ctx`.
    ///
    /// Returns findings. An empty vector means no issues detected.
    /// Errors represent infrastructure failures, not absence of vulnerabilities.
    async fn run(&self, ctx: &ScanContext) -> Result<Vec<Finding>>;

    /// Whether this module requires an external tool to be installed.
    fn requires_external_tool(&self) -> bool {
        false     // default: built-in module
    }

    /// The external tool binary name this module needs.
    fn required_tool(&self) -> Option<&str> {
        None      // default: no external tool
    }
}
```

### Required methods (5)

| Method | Returns | Purpose |
|--------|---------|---------|
| `name()` | `&str` | Display name (e.g., "Reflected XSS Detection") |
| `id()` | `&str` | Short slug for CLI (e.g., "xss") |
| `category()` | `ModuleCategory` | `Recon` or `Scanner` |
| `description()` | `&str` | One-line description |
| `run()` | `Result<Vec<Finding>>` | Execute the scan |

### Optional methods (2, with defaults)

| Method | Default | Override when... |
|--------|---------|-----------------|
| `requires_external_tool()` | `false` | Module wraps an external binary |
| `required_tool()` | `None` | Module needs a specific binary in `PATH` |

### ModuleCategory

```rust
pub enum ModuleCategory {
    Recon,    // Information gathering
    Scanner,  // Vulnerability detection
}
```

### ScanContext

The `ScanContext` is the shared environment passed to every module's `run()`:

```rust
pub struct ScanContext {
    pub target: Target,              // URL, domain, port, scheme
    pub config: Arc<AppConfig>,      // Full application config
    pub http_client: reqwest::Client,// Shared HTTP client (proxy, TLS, cookies)
    pub shared_data: Arc<SharedData>,// Inter-module data store
}
```

---

## Adding a New Scanner Module

This walkthrough creates a hypothetical "Open Redirect" scanner. The
reference template is `src/scanner/xss.rs`.

### Step 1: Create the module file

Create `src/scanner/open_redirect.rs`:

```rust
use async_trait::async_trait;

use crate::engine::error::{Result, ScorchError};
use crate::engine::finding::Finding;
use crate::engine::module_trait::{ModuleCategory, ScanModule};
use crate::engine::scan_context::ScanContext;
use crate::engine::severity::Severity;

/// Detects open redirect vulnerabilities in URL parameters.
#[derive(Debug)]
pub struct OpenRedirectModule;

#[async_trait]
impl ScanModule for OpenRedirectModule {
    fn name(&self) -> &'static str {
        "Open Redirect Detection"
    }

    fn id(&self) -> &'static str {
        "open-redirect"
    }

    fn category(&self) -> ModuleCategory {
        ModuleCategory::Scanner
    }

    fn description(&self) -> &'static str {
        "Detect open redirect vulnerabilities in URL parameters"
    }

    async fn run(&self, ctx: &ScanContext) -> Result<Vec<Finding>> {
        let url = ctx.target.url.as_str();
        let mut findings = Vec::new();

        // Fetch the page
        let response = ctx
            .http_client
            .get(url)
            .send()
            .await
            .map_err(|e| ScorchError::Http {
                url: url.to_string(),
                source: e,
            })?;

        let body = response.text().await.unwrap_or_default();

        // Extract links with redirect-like parameters
        let redirect_params = extract_redirect_params(&body, url);
        for (param_url, param_name) in &redirect_params {
            test_redirect(ctx, param_url, param_name, &mut findings).await?;
        }

        // Also check URLs from the shared crawler data
        let shared_urls = ctx.shared_data.get(
            crate::engine::shared_data::keys::URLS,
        );
        for shared_url in &shared_urls {
            let params = extract_redirect_params_from_url(shared_url);
            for (param_url, param_name) in &params {
                test_redirect(ctx, param_url, param_name, &mut findings)
                    .await?;
            }
        }

        Ok(findings)
    }
}

/// Redirect-related parameter names to test.
const REDIRECT_PARAMS: &[&str] = &[
    "url", "redirect", "redirect_uri", "return", "return_to",
    "next", "dest", "destination", "rurl", "target",
];

/// Test a single URL parameter for open redirect.
async fn test_redirect(
    ctx: &ScanContext,
    url: &str,
    param_name: &str,
    findings: &mut Vec<Finding>,
) -> Result<()> {
    let canary = "https://evil.example.com";

    // Build the test URL with the canary injected
    let test_url = inject_param(url, param_name, canary);

    let Ok(response) = ctx
        .http_client
        .get(&test_url)
        .send()
        .await
    else {
        return Ok(());
    };

    // Check if the response redirects to our canary
    let final_url = response.url().as_str();
    if final_url.contains("evil.example.com") {
        findings.push(
            Finding::new(
                "open-redirect",
                Severity::Medium,
                format!("Open Redirect via Parameter: {param_name}"),
                format!(
                    "The parameter '{param_name}' accepts arbitrary external URLs \
                     and redirects the user without validation."
                ),
                url,
            )
            .with_evidence(format!(
                "Parameter: {param_name} | Injected: {canary} | \
                 Redirected to: {final_url}"
            ))
            .with_remediation(
                "Validate redirect targets against an allowlist of \
                 trusted domains. Never redirect to user-supplied URLs \
                 without validation.",
            )
            .with_owasp("A01:2021 Broken Access Control")
            .with_cwe(601)
            .with_confidence(0.85),
        );
    }

    Ok(())
}

// Pure helper functions (testable without HTTP)

fn extract_redirect_params(body: &str, base_url: &str) -> Vec<(String, String)> {
    // ... parse HTML for links containing redirect-like parameters
    let _ = (body, base_url);
    Vec::new() // placeholder
}

fn extract_redirect_params_from_url(url: &str) -> Vec<(String, String)> {
    // ... extract redirect-like query parameters from a URL
    let _ = url;
    Vec::new() // placeholder
}

fn inject_param(url: &str, param: &str, value: &str) -> String {
    // Replace the parameter value in the URL
    let _ = (url, param, value);
    String::new() // placeholder
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_redirect_params_list_is_nonempty() {
        assert!(!REDIRECT_PARAMS.is_empty());
    }

    #[test]
    fn test_inject_param_replaces_value() {
        // Test your pure inject_param function here
        // No HTTP, no mocking -- just input/output
    }
}
```

### Step 2: Register in `src/scanner/mod.rs`

Add the module declaration and register it:

```rust
// Add the module declaration at the top
mod open_redirect;

// Add to register_modules()
pub fn register_modules() -> Vec<Box<dyn ScanModule>> {
    vec![
        // ... existing modules ...
        Box::new(open_redirect::OpenRedirectModule),
    ]
}
```

### Step 3: Run the quality gates

```bash
cargo fmt           # Format code
cargo clippy        # Zero warnings required
cargo test          # All tests must pass
```

That is the complete process. The orchestrator discovers the module
automatically through `register_modules()`.

---

## Adding a New Recon Module

Recon modules gather information rather than test for vulnerabilities. The
reference template is `src/recon/headers.rs`.

The structure is identical to scanner modules, with two differences:

1. The `category()` method returns `ModuleCategory::Recon`
2. Recon modules often publish data to `SharedData` for downstream scanners

### Example: Technology Fingerprinting Recon Module

```rust
use async_trait::async_trait;

use crate::engine::error::{Result, ScorchError};
use crate::engine::finding::Finding;
use crate::engine::module_trait::{ModuleCategory, ScanModule};
use crate::engine::scan_context::ScanContext;
use crate::engine::severity::Severity;

/// Detects web server technology from response headers.
#[derive(Debug)]
pub struct ServerFingerprintModule;

#[async_trait]
impl ScanModule for ServerFingerprintModule {
    fn name(&self) -> &'static str {
        "Server Fingerprint"
    }

    fn id(&self) -> &'static str {
        "server-fingerprint"
    }

    fn category(&self) -> ModuleCategory {
        ModuleCategory::Recon   // <-- Recon, not Scanner
    }

    fn description(&self) -> &'static str {
        "Fingerprint web server technology from response headers"
    }

    async fn run(&self, ctx: &ScanContext) -> Result<Vec<Finding>> {
        let url = ctx.target.url.as_str();

        let response = ctx
            .http_client
            .get(url)
            .send()
            .await
            .map_err(|e| ScorchError::Http {
                url: url.to_string(),
                source: e,
            })?;

        let headers = response.headers().clone();
        let mut findings = Vec::new();

        // Extract technology indicators from headers
        let techs = detect_technologies(&headers);

        for tech in &techs {
            findings.push(
                Finding::new(
                    "server-fingerprint",
                    Severity::Info,
                    format!("Detected Technology: {tech}"),
                    format!("The server appears to be running {tech}."),
                    url,
                )
                .with_owasp("A05:2021 Security Misconfiguration")
                .with_confidence(0.7),
            );
        }

        // Publish for downstream modules (scanner modules can read this)
        ctx.shared_data.publish(
            crate::engine::shared_data::keys::TECHNOLOGIES,
            techs,
        );

        Ok(findings)
    }
}

/// Detect technologies from HTTP response headers.
fn detect_technologies(headers: &reqwest::header::HeaderMap) -> Vec<String> {
    let mut techs = Vec::new();

    if let Some(server) = headers.get("server") {
        if let Ok(val) = server.to_str() {
            techs.push(val.to_string());
        }
    }

    if let Some(powered) = headers.get("x-powered-by") {
        if let Ok(val) = powered.to_str() {
            techs.push(val.to_string());
        }
    }

    techs
}

#[cfg(test)]
mod tests {
    use super::*;
    use reqwest::header::HeaderMap;

    #[test]
    fn test_detect_technologies_from_server_header() {
        let mut headers = HeaderMap::new();
        headers.insert("server", "nginx/1.24.0".parse().unwrap());

        let techs = detect_technologies(&headers);
        assert_eq!(techs.len(), 1);
        assert!(techs[0].contains("nginx"));
    }

    #[test]
    fn test_detect_technologies_empty_headers() {
        let headers = HeaderMap::new();
        let techs = detect_technologies(&headers);
        assert!(techs.is_empty());
    }
}
```

Register in `src/recon/mod.rs`:

```rust
mod server_fingerprint;

pub fn register_modules() -> Vec<Box<dyn ScanModule>> {
    vec![
        // ... existing modules ...
        Box::new(server_fingerprint::ServerFingerprintModule),
    ]
}
```

---

## Adding a New Tool Wrapper

Tool wrappers execute an external binary and parse its output. The reference
template is `src/tools/nmap.rs`.

Key differences from built-in modules:

- Override `requires_external_tool()` to return `true`
- Override `required_tool()` to return the binary name
- Use `crate::runner::subprocess::run_tool()` for execution
- Parse stdout into findings using pure functions

### Example: Nikto Tool Wrapper

```rust
use std::time::Duration;

use async_trait::async_trait;

use crate::engine::error::Result;
use crate::engine::finding::Finding;
use crate::engine::module_trait::{ModuleCategory, ScanModule};
use crate::engine::scan_context::ScanContext;
use crate::engine::severity::Severity;
use crate::runner::subprocess;

/// Web server vulnerability scanner via nikto.
#[derive(Debug)]
pub struct NiktoModule;

#[async_trait]
impl ScanModule for NiktoModule {
    fn name(&self) -> &'static str {
        "Nikto Web Scanner"
    }

    fn id(&self) -> &'static str {
        "nikto"
    }

    fn category(&self) -> ModuleCategory {
        ModuleCategory::Scanner
    }

    fn description(&self) -> &'static str {
        "Web server vulnerability scanning via nikto"
    }

    // Tool wrappers MUST override these two methods:
    fn requires_external_tool(&self) -> bool {
        true
    }

    fn required_tool(&self) -> Option<&str> {
        Some("nikto")
    }

    async fn run(&self, ctx: &ScanContext) -> Result<Vec<Finding>> {
        let target = ctx.target.url.as_str();

        // Use subprocess::run_tool for managed execution with timeout
        let output = subprocess::run_tool(
            "nikto",
            &["-h", target, "-Format", "json", "-output", "-"],
            Duration::from_secs(300),
        )
        .await?;

        // Parse output in a pure function (testable without subprocess)
        Ok(parse_nikto_output(&output.stdout, target))
    }
}

/// Parse nikto JSON output into findings.
///
/// This is a pure function -- no I/O, no async, fully unit-testable.
fn parse_nikto_output(stdout: &str, target_url: &str) -> Vec<Finding> {
    let mut findings = Vec::new();

    // Parse the JSON output and create findings
    for line in stdout.lines() {
        let line = line.trim();
        if line.is_empty() {
            continue;
        }
        // ... parse each vulnerability entry ...
        findings.push(
            Finding::new(
                "nikto",
                Severity::Medium,
                "Nikto Finding",
                line,
                target_url,
            )
            .with_confidence(0.6),
        );
    }

    findings
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Test the pure parsing function -- no subprocess needed.
    #[test]
    fn test_parse_nikto_output_empty() {
        let findings = parse_nikto_output("", "https://example.com");
        assert!(findings.is_empty());
    }

    #[test]
    fn test_parse_nikto_output_with_results() {
        let output = "Server: Apache/2.4.41 - outdated\n";
        let findings = parse_nikto_output(output, "https://example.com");
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].module_id, "nikto");
    }
}
```

### The `subprocess::run_tool` function

Located at `src/runner/subprocess.rs`, this is the standard way to run
external tools:

```rust
pub async fn run_tool(
    tool_name: &str,       // Binary name (must be in PATH)
    args: &[&str],         // Command arguments
    timeout: Duration,     // Maximum execution time
) -> Result<ToolOutput>
```

It returns:

```rust
pub struct ToolOutput {
    pub stdout: String,
    pub stderr: String,
    pub exit_code: i32,
    pub duration: Duration,
}
```

Error cases:
- `ScorchError::ToolNotFound` -- binary not in PATH
- `ScorchError::ToolFailed` -- non-zero exit code
- `ScorchError::Cancelled` -- timeout exceeded

Tool wrappers are registered in `src/tools/mod.rs` following the same pattern
as scanner and recon modules.

---

## Finding Builder Pattern

`Finding` (defined in `src/engine/finding.rs`) uses a builder pattern. You
create a finding with `Finding::new()` and chain optional builder methods.

### Constructor (required fields)

```rust
Finding::new(
    module_id,          // impl Into<String> -- your module's id()
    severity,           // Severity enum value
    title,              // impl Into<String> -- short title
    description,        // impl Into<String> -- detailed description
    affected_target,    // impl Into<String> -- URL, header, parameter
)
```

### Builder methods (all optional, all return `Self`)

| Method | Parameter | Purpose |
|--------|-----------|---------|
| `.with_evidence(impl Into<String>)` | Raw evidence string | Response snippet, header value, tool output |
| `.with_remediation(impl Into<String>)` | Fix suggestion | How to resolve the issue |
| `.with_owasp(impl Into<String>)` | OWASP category | e.g., "A03:2021 Injection" |
| `.with_cwe(u32)` | CWE ID | e.g., 79 for XSS |
| `.with_confidence(f64)` | 0.0--1.0 | Certainty this is a true positive (default: 0.5) |
| `.with_compliance(Vec<String>)` | Control references | NIST, PCI-DSS, SOC2, HIPAA controls |
| `.with_http_evidence(HttpEvidence)` | Full HTTP capture | Request/response pair for PoC replay |

### Complete example

```rust
use crate::engine::evidence::HttpEvidence;
use crate::engine::finding::Finding;
use crate::engine::severity::Severity;

let finding = Finding::new(
    "xss",
    Severity::High,
    "Reflected XSS in Parameter: q",
    "The parameter 'q' reflects user input without proper encoding.",
    "https://example.com/search?q=test",
)
.with_evidence("Parameter: q | Payload: <script>alert(1)</script>")
.with_remediation(
    "Encode all user input before rendering in HTML. \
     Use context-appropriate encoding.",
)
.with_owasp("A03:2021 Injection")
.with_cwe(79)
.with_confidence(0.85)
.with_compliance(vec![
    "PCI-DSS 6.5.7".to_string(),
    "NIST SP 800-53 SI-10".to_string(),
])
.with_http_evidence(
    HttpEvidence::new("GET", "https://example.com/search?q=<script>", 200)
        .with_response_body("<html><script>alert(1)</script></html>"),
);
```

### Confidence score guidelines

| Score | Meaning | When to use |
|-------|---------|-------------|
| 0.9--1.0 | Near-certain | Header missing, confirmed reflection |
| 0.7--0.9 | High confidence | Payload reflected, canary detected |
| 0.5--0.7 | Medium confidence | Heuristic match, pattern-based |
| 0.3--0.5 | Low confidence | Indirect indicator, tool output |
| 0.0--0.3 | Speculative | Educated guess, anomaly-based |

The `--min-confidence` CLI flag lets users hide findings below a threshold.

### Severity enum

```rust
pub enum Severity {
    Info,       // Informational observations
    Low,        // Minor issues, minimal impact
    Medium,     // Moderate risk, should be fixed
    High,       // Serious vulnerability, fix soon
    Critical,   // Severe, exploit likely, fix immediately
}
```

---

## Inter-Module Communication with SharedData

Modules run concurrently but can share discovered data through `SharedData`,
a thread-safe key-value store on `ScanContext`. Recon modules typically
publish data that scanner modules consume.

### Well-known keys

Defined in `src/engine/shared_data.rs`:

```rust
pub mod keys {
    pub const URLS: &str = "urls";              // Discovered URLs
    pub const FORMS: &str = "forms";            // Form endpoint URLs
    pub const PARAMS: &str = "params";          // Query parameter names
    pub const TECHNOLOGIES: &str = "technologies"; // Detected tech stack
    pub const SUBDOMAINS: &str = "subdomains";  // Discovered subdomains
}
```

### Publishing data (producer module)

From the crawler module (`src/recon/crawler.rs`):

```rust
use crate::engine::shared_data::keys;

// Inside run():
ctx.shared_data.publish(
    keys::URLS,
    discovered_urls.iter().cloned().collect(),
);
ctx.shared_data.publish(
    keys::FORMS,
    discovered_forms.iter().map(|f| f.url.clone()).collect(),
);
ctx.shared_data.publish(
    keys::PARAMS,
    discovered_params.iter().cloned().collect(),
);
```

### Consuming data (consumer module)

From the XSS scanner (`src/scanner/xss.rs`):

```rust
// Inside run():
let shared_urls = ctx.shared_data.get(
    crate::engine::shared_data::keys::URLS,
);
for shared_url in &shared_urls {
    if shared_url != url && !links.contains(shared_url) {
        test_url_params_xss(ctx, shared_url, &mut findings).await?;
    }
}
```

### API

```rust
impl SharedData {
    /// Publish values under a key (extends existing entries).
    pub fn publish(&self, key: &str, values: Vec<String>);

    /// Read all values for a key (empty vec if missing).
    pub fn get(&self, key: &str) -> Vec<String>;

    /// Check if a key has any published data.
    pub fn has(&self, key: &str) -> bool;
}
```

Thread safety is handled internally via `RwLock`. You do not need to lock
anything manually.

---

## Testing Patterns

ScorchKit tests pure functions, not HTTP interactions. The project does not
use HTTP mocking libraries. The pattern is:

1. **Extract logic into pure helper functions** that take strings, headers,
   or parsed data as input.
2. **Test those helper functions** with known inputs and expected outputs.
3. **The `run()` method** handles HTTP and delegates to the pure functions.

### Pattern: Test pure parsing functions

From `src/tools/nmap.rs` -- the nmap XML parser is a pure function:

```rust
/// Parse nmap XML output into findings.
fn parse_nmap_xml(xml: &str, target_url: &str) -> Vec<Finding> {
    // ... parsing logic ...
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_nmap_xml() {
        let xml = r#"<?xml version="1.0"?>
<nmaprun>
<host><ports>
<port protocol="tcp" portid="80">
  <state state="open"/>
  <service name="http" product="nginx" version="1.18.0"/>
</port>
<port protocol="tcp" portid="3306">
  <state state="open"/>
  <service name="mysql" product="MySQL" version="8.0.30"/>
</port>
</ports></host>
</nmaprun>"#;

        let findings = parse_nmap_xml(xml, "https://example.com");
        assert_eq!(findings.len(), 2);
        assert!(findings[0].title.contains("80"));
        assert_eq!(findings[0].severity, Severity::Info);
        assert!(findings[1].title.contains("3306"));
        assert_eq!(findings[1].severity, Severity::High); // database port
    }

    #[test]
    fn test_parse_nmap_xml_empty() {
        let findings = parse_nmap_xml("", "https://example.com");
        assert!(findings.is_empty());
    }
}
```

### Pattern: Test header analysis helpers

From `src/recon/headers.rs` -- header-checking functions take `HeaderMap`:

```rust
fn extract_max_age(hsts_value: &str) -> Option<u64> { /* ... */ }
fn has_csp_frame_ancestors(headers: &reqwest::header::HeaderMap) -> bool { /* ... */ }

#[cfg(test)]
mod tests {
    use super::*;
    use reqwest::header::HeaderMap;

    #[test]
    fn test_extract_max_age_valid() {
        assert_eq!(extract_max_age("max-age=31536000"), Some(31_536_000));
    }

    #[test]
    fn test_extract_max_age_with_extra_directives() {
        assert_eq!(
            extract_max_age("max-age=63072000; includeSubDomains; preload"),
            Some(63_072_000),
        );
    }

    #[test]
    fn test_extract_max_age_invalid() {
        assert_eq!(extract_max_age("max-age=abc"), None);
    }

    #[test]
    fn test_has_csp_frame_ancestors_present()
        -> std::result::Result<(), Box<dyn std::error::Error>>
    {
        let mut headers = HeaderMap::new();
        headers.insert(
            "content-security-policy",
            "default-src 'self'; frame-ancestors 'none'".parse()?,
        );
        assert!(has_csp_frame_ancestors(&headers));
        Ok(())
    }
}
```

### Pattern: Test HTML parsing helpers

From `src/scanner/xss.rs` -- link and form extraction:

```rust
#[test]
fn test_extract_parameterized_links()
    -> std::result::Result<(), url::ParseError>
{
    let base = Url::parse("https://example.com/")?;
    let body = r#"
        <html><body>
            <a href="/search?q=test&lang=en">Search</a>
            <a href="https://example.com/page?id=42">Page</a>
            <a href="/about">About</a>
            <a href="https://other.com/x?y=1">External</a>
        </body></html>
    "#;

    let links = extract_parameterized_links(body, &base);

    assert_eq!(links.len(), 2);
    assert!(links.iter().any(|l| l.contains("search?q=test")));
    assert!(links.iter().any(|l| l.contains("page?id=42")));
    assert!(!links.iter().any(|l| l.contains("other.com")));

    Ok(())
}
```

### Test naming conventions

Use the `Arrange / Act / Assert` pattern and descriptive doc comments:

```rust
/// Verify `extract_max_age` parses a valid max-age value from an HSTS header.
#[test]
fn test_extract_max_age_valid() {
    // Arrange
    let hsts = "max-age=31536000";

    // Act
    let result = extract_max_age(hsts);

    // Assert
    assert_eq!(result, Some(31_536_000));
}
```

### Running tests

```bash
cargo test                          # Default tests (~178)
cargo test --features mcp           # All tests (~287, includes MCP/storage)
cargo test -- --test-threads=1      # Serial execution if needed
```

---

## Quality Standards

ScorchKit enforces strict quality standards via Cargo.toml lint configuration
and CI hooks. Every module must meet these requirements.

### Clippy: zero warnings

The project enables `pedantic` and `nursery` lint groups and denies
`unwrap_used`, `expect_used`, and `unsafe_code`:

```toml
# From Cargo.toml
[lints.rust]
unsafe_code = "deny"

[lints.clippy]
pedantic = { level = "warn", priority = -1 }
nursery = { level = "warn", priority = -1 }
unwrap_used = "deny"
expect_used = "deny"
```

This means:

- **No `.unwrap()` or `.expect()` anywhere** -- use `?`, `map_err()`,
  `unwrap_or_default()`, or pattern matching instead.
- **No `unsafe` code.**
- **Zero clippy warnings** -- run `cargo clippy` before committing.

### `#[allow]` requires justification

If you must suppress a lint, add a `JUSTIFICATION` comment:

```rust
// JUSTIFICATION: CLI dispatch function -- match arms are the natural
// structure; extraction would scatter dispatch logic
#[allow(clippy::too_many_lines)]
pub async fn execute(cli: Cli) -> Result<()> {
```

Never add crate-level lint suppressions. Never use `#[ignore]` on tests.

### Formatting

Run `cargo fmt` before every commit. The CI hooks enforce this.

### Doc comments

Every public type, function, and method must have a doc comment (`///`).
Module files should have a module-level doc comment (`//!`).

```rust
/// Parse nmap XML output into findings.
///
/// Extracts open ports and service information from well-formed
/// nmap `-oX` output.
fn parse_nmap_xml(xml: &str, target_url: &str) -> Vec<Finding> {
```

### Error handling patterns

Use the project's error type consistently:

```rust
use crate::engine::error::{Result, ScorchError};

// For HTTP errors:
let response = ctx.http_client
    .get(url)
    .send()
    .await
    .map_err(|e| ScorchError::Http {
        url: url.to_string(),
        source: e,
    })?;

// For non-critical failures (skip, don't fail the scan):
let Ok(response) = ctx.http_client.get(url).send().await else {
    return Ok(());
};

// For tool output parsing:
return Err(ScorchError::ToolOutputParse {
    tool: "nikto".to_string(),
    reason: "unexpected JSON format".to_string(),
});
```

### Quality gate commands

Run these before every commit:

```bash
cargo fmt                # Format
cargo clippy             # Lint (must be zero warnings)
cargo test               # Tests (must all pass)
```

---

## Plugin System

ScorchKit supports user-defined modules via TOML plugin definitions, loaded
from a plugins directory. Plugins wrap external commands and integrate with
the orchestrator as first-class `ScanModule` implementations.

### Plugin definition file

Create a `.toml` file in the plugins directory:

```toml
# plugins/custom-check.toml
id = "custom-check"
name = "My Custom Check"
description = "Runs a custom security check"
category = "scanner"           # "scanner" or "recon"
command = "my-tool"            # Binary name (must be in PATH)
args = ["--json", "{target}"]  # {target} is replaced with the scan URL
timeout_seconds = 120          # Max execution time (default: 120)
output_format = "json_lines"   # "lines", "json_lines", or "json"
severity = "medium"            # Default severity for findings
```

### Plugin definition fields

| Field | Required | Default | Description |
|-------|----------|---------|-------------|
| `id` | Yes | -- | Unique module identifier |
| `name` | Yes | -- | Human-readable display name |
| `description` | Yes | -- | What this plugin checks |
| `category` | No | `"scanner"` | `"recon"` or `"scanner"` |
| `command` | Yes | -- | External binary to execute |
| `args` | No | `[]` | Arguments; `{target}` is replaced with the scan URL |
| `timeout_seconds` | No | `120` | Maximum execution time in seconds |
| `output_format` | No | `"lines"` | How to parse stdout |
| `severity` | No | `"info"` | Default severity for findings |

### Output formats

**`lines`** (default): All non-empty lines consolidated into a single finding
with a count and sample.

**`json_lines`**: Each line is a JSON object parsed into a separate finding.
Expected fields: `title` (or `name`), `description` (or `message`),
`severity`.

```json
{"title": "XSS Found", "severity": "high", "description": "Reflected XSS in /search"}
{"title": "SQLi Found", "severity": "critical", "description": "SQL Injection in /api"}
```

**`json`**: Stdout is a single JSON array. Each element becomes a finding.

```json
[
  {"title": "Issue 1", "severity": "medium", "description": "..."},
  {"title": "Issue 2", "severity": "low", "description": "..."}
]
```

### How plugins are loaded

The `load_plugins()` function in `src/runner/plugin.rs` scans a directory
for `.toml` files, deserializes each into a `PluginDef`, and wraps it in a
`PluginModule` that implements `ScanModule`. Invalid files are logged and
skipped.

Plugins always report `requires_external_tool() == true` and
`required_tool() == Some("command_name")`.

---

## Adding CLI Commands and Flags

The CLI is built with [clap](https://docs.rs/clap) using derive macros.
Definitions live in `src/cli/args.rs`.

### Adding a flag to an existing command

To add a new flag to the `run` command, add a field to the `Run` variant:

```rust
// In src/cli/args.rs, inside Commands::Run { ... }

/// Maximum number of concurrent modules
#[arg(long, default_value = "10")]
concurrency: usize,
```

Then handle it in `src/cli/runner.rs` where the `Run` command is dispatched:

```rust
Commands::Run {
    target,
    concurrency,  // <-- destructure the new field
    // ... other fields ...
} => {
    // Use concurrency in the orchestrator config
}
```

### Adding a new subcommand

Add a new variant to the `Commands` enum:

```rust
#[derive(Subcommand, Debug)]
pub enum Commands {
    // ... existing commands ...

    /// Export findings to an external system
    Export {
        /// Path to the scan report
        report: PathBuf,

        /// Export format: jira, github, csv
        #[arg(short, long, default_value = "csv")]
        format: String,

        /// Output file path
        #[arg(short, long)]
        output: Option<PathBuf>,
    },
}
```

Then add a match arm in `src/cli/runner.rs`:

```rust
Commands::Export { report, format, output } => {
    // Implement export logic
}
```

### Feature-gated commands

Commands that require optional dependencies use `#[cfg(feature = "...")]`:

```rust
/// Start the MCP server on stdio transport
#[cfg(feature = "mcp")]
Serve,
```

### Output format enum

```rust
#[derive(Debug, Clone, ValueEnum)]
pub enum OutputFormat {
    Terminal,
    Json,
    Html,
    Sarif,
    Pdf,
}
```

Global flags (`--config`, `--verbose`, `--quiet`, `--output`) are defined on
the top-level `Cli` struct and available to all subcommands.

---

## Checklist: Adding a New Module

Use this checklist whenever you add a new module:

- [ ] Create `src/{recon,scanner,tools}/your_module.rs`
- [ ] Implement `ScanModule` trait with all 5 required methods
- [ ] For tool wrappers: override `requires_external_tool()` and `required_tool()`
- [ ] Use `Finding::new(...).with_*()` builder for all findings
- [ ] Set appropriate confidence scores on every finding
- [ ] Include OWASP category and CWE ID where applicable
- [ ] Extract logic into pure helper functions for testing
- [ ] Write unit tests for every pure helper function
- [ ] Add `mod your_module;` declaration in the parent `mod.rs`
- [ ] Register with `Box::new(your_module::YourModule)` in `register_modules()`
- [ ] Run `cargo fmt`
- [ ] Run `cargo clippy` (zero warnings)
- [ ] Run `cargo test` (all pass)
- [ ] Add doc comments to all public items
- [ ] No `.unwrap()` or `.expect()` calls
- [ ] No `#[allow]` without a `JUSTIFICATION` comment
