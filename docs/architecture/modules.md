# Writing Scan Modules

This is the guide for adding new scan modules to ScorchKit. Every scanner - whether it performs built-in analysis or wraps an external tool - implements the `ScanModule` trait.

## The ScanModule Trait

```rust
#[async_trait]
pub trait ScanModule: Send + Sync {
    /// Human-readable name for display. E.g., "HTTP Security Headers"
    fn name(&self) -> &str;

    /// Short identifier for CLI flags and config. E.g., "headers"
    fn id(&self) -> &str;

    /// Recon or Scanner
    fn category(&self) -> ModuleCategory;

    /// One-line description. E.g., "Analyze HTTP security headers..."
    fn description(&self) -> &str;

    /// Run the scan. Returns findings (empty vec = no issues).
    /// Errors = infrastructure failure, not "no vulnerabilities found".
    async fn run(&self, ctx: &ScanContext) -> Result<Vec<Finding>>;

    /// Override to true if this module wraps an external tool.
    fn requires_external_tool(&self) -> bool { false }

    /// Return the binary name needed. E.g., "nmap"
    fn required_tool(&self) -> Option<&str> { None }
}
```

## Step-by-Step: Adding a Built-in Module

### 1. Create the module file

Create `src/recon/my_module.rs` or `src/scanner/my_module.rs`:

```rust
use async_trait::async_trait;

use crate::engine::error::{Result, ScorchError};
use crate::engine::finding::Finding;
use crate::engine::module_trait::{ModuleCategory, ScanModule};
use crate::engine::scan_context::ScanContext;
use crate::engine::severity::Severity;

#[derive(Debug)]
pub struct MyModule;

#[async_trait]
impl ScanModule for MyModule {
    fn name(&self) -> &'static str {
        "My Security Check"
    }

    fn id(&self) -> &'static str {
        "my-check"
    }

    fn category(&self) -> ModuleCategory {
        ModuleCategory::Recon  // or ModuleCategory::Scanner
    }

    fn description(&self) -> &'static str {
        "Checks for something specific"
    }

    async fn run(&self, ctx: &ScanContext) -> Result<Vec<Finding>> {
        let url = ctx.target.url.as_str();
        let mut findings = Vec::new();

        // Use ctx.http_client for HTTP requests
        let response = ctx.http_client
            .get(url)
            .send()
            .await
            .map_err(|e| ScorchError::Http {
                url: url.to_string(),
                source: e,
            })?;

        // Analyze response, create findings
        if some_condition {
            findings.push(
                Finding::new(
                    "my-check",           // must match id()
                    Severity::Medium,
                    "Issue Title",
                    "Detailed description of the issue",
                    url,
                )
                .with_evidence("raw evidence string")
                .with_remediation("How to fix this")
                .with_owasp("A05:2021 Security Misconfiguration")
                .with_cwe(693),
            );
        }

        Ok(findings)
    }
}
```

### 2. Declare the module

Add to `src/recon/mod.rs` (or `src/scanner/mod.rs`):

```rust
mod my_module;
```

### 3. Register the module

Add to the `register_modules()` function in the same `mod.rs`:

```rust
pub fn register_modules() -> Vec<Box<dyn ScanModule>> {
    vec![
        Box::new(headers::HeadersModule),
        Box::new(tech::TechModule),
        Box::new(discovery::DiscoveryModule),
        Box::new(subdomain::SubdomainModule),
        Box::new(crawler::CrawlerModule),
        Box::new(dns::DnsSecurityModule),
        Box::new(my_module::MyModule),  // Add this line
    ]
}
```

That's it. The orchestrator will automatically discover, run, and report findings from the new module.

## Step-by-Step: Adding an External Tool Wrapper

### 1. Create the wrapper

```rust
use async_trait::async_trait;
use std::time::Duration;

use crate::engine::error::{Result, ScorchError};
use crate::engine::finding::Finding;
use crate::engine::module_trait::{ModuleCategory, ScanModule};
use crate::engine::scan_context::ScanContext;
use crate::engine::severity::Severity;
use crate::runner::subprocess;

#[derive(Debug)]
pub struct NmapModule;

#[async_trait]
impl ScanModule for NmapModule {
    fn name(&self) -> &'static str { "Nmap Port Scanner" }
    fn id(&self) -> &'static str { "nmap" }
    fn category(&self) -> ModuleCategory { ModuleCategory::Scanner }
    fn description(&self) -> &'static str { "Port scanning and service detection via nmap" }

    fn requires_external_tool(&self) -> bool { true }
    fn required_tool(&self) -> Option<&str> { Some("nmap") }

    async fn run(&self, ctx: &ScanContext) -> Result<Vec<Finding>> {
        let target = ctx.target.domain.as_deref()
            .unwrap_or(ctx.target.url.as_str());

        let output = subprocess::run_tool(
            "nmap",
            &["-sV", "-oX", "-", target],
            Duration::from_secs(300),
        ).await?;

        parse_nmap_output(&output.stdout, ctx.target.url.as_str())
    }
}

fn parse_nmap_output(xml: &str, target_url: &str) -> Result<Vec<Finding>> {
    // Parse the tool's output format into Vec<Finding>
    let mut findings = Vec::new();
    // ... parsing logic ...
    Ok(findings)
}
```

### 2. Register

Same as built-in modules. The orchestrator will check tool availability before running and skip gracefully if the tool isn't installed.

## Module Counts

ScorchKit ships with 63 modules across four categories:

| Category | Count | Location |
|----------|-------|----------|
| Recon | 6 | `src/recon/` — headers, tech, discovery, subdomain, crawler, dns |
| Scanner | 24 | `src/scanner/` — ssl, misconfig, csrf, injection, cmdi, xss, ssrf, xxe, idor, jwt, redirect, sensitive, api-schema, ratelimit, cors-deep, csp-deep, auth-session, upload, websocket, graphql, subtakeover, acl, api-security, waf |
| Tools | 32 | `src/tools/` — amass, arjun, cewl, dalfox, dnsrecon, dnsx, droopescan, enum4linux, feroxbuster, ffuf, gau, gobuster, httpx, hydra, interactsh, katana, metasploit, nikto, nmap, nuclei, paramspider, prowler, sqlmap, sslyze, subfinder, testssl, theharvester, trivy, trufflehog, wafw00f, wpscan, zap |
| User Plugins | variable | Loaded from TOML files via `runner::plugin::load_plugins()` |

## What the Orchestrator Provides

Your module receives a `ScanContext` with:

- **`ctx.target`** - Parsed target with URL, domain, port, TLS status
- **`ctx.config`** - Full `AppConfig` (scan settings, tool paths, etc.)
- **`ctx.http_client`** - Pre-configured `reqwest::Client` with:
  - User-Agent set
  - Redirect policy configured
  - Connection pooling enabled
  - TLS certificate validation on

## Finding Best Practices

1. **`module_id` must match `id()`** - This links findings to their source module
2. **Include OWASP category** when applicable - e.g., `"A05:2021 Security Misconfiguration"`
3. **Include CWE ID** when there's a direct mapping
4. **Use `.with_compliance()`** when OWASP/CWE is set - auto-maps to NIST/PCI-DSS/SOC2/HIPAA via `engine::compliance`
5. **Use `.with_http_evidence()`** for PoC replay - attach the full request/response pair via `engine::evidence::HttpEvidence`
6. **Evidence should be raw data** - the actual header value, response snippet, or tool output
7. **Remediation should be actionable** - specific header to add, config to change, etc.
8. **Return empty vec for clean scans** - don't create "info" findings just to say "everything OK"
9. **Return `Err` only for infrastructure failures** - tool not responding, network down, parse error. NOT for "no vulnerabilities found"

## Conventions

- Module IDs are lowercase, hyphenated: `headers`, `ssl`, `tech-fingerprint`, `dir-discovery`
- Module names are human-readable: "HTTP Security Headers", "TLS/SSL Analysis"
- One struct per module file
- Helper/parser functions are private to the module file
- Use `&'static str` for name/id/description returns (they're string literals)
