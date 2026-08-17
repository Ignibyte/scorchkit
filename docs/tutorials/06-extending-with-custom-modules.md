# 06 — Extend ScorchKit with a Rust module

This tutorial adds a trusted in-process module. ScorchKit does not expose a stable binary plugin ABI,
and Rust extensions run with the privileges of the host process. Review extension code as part of
ScorchKit itself.

The complete public contract is in [the Rust module extension API](../plugin-sdk.md). The repository
also contains two standalone crates that compile against the current checkout:

- `examples/custom_scanner` for DAST;
- `examples/custom_code_scanner` for SAST.

## Choose the module family

| Trait | Context | Intended work |
|---|---|---|
| `ScanModule` | `ScanContext` | URL-based DAST and reconnaissance |
| `CodeModule` | `CodeContext` | local static analysis and dependency checks |
| `InfraModule` | `InfraContext` | host, address, protocol, and network checks |
| `CloudModule` | `CloudContext` | cloud posture checks |

The infrastructure and cloud traits require their matching Cargo features.

## Implement a small DAST module

The following module reports an `X-Powered-By` header that contains a version. It uses the HTTP
client supplied by the context. That client enforces the engagement for the URL, redirects,
hostname, and every resolved address.

```rust,no_run
use async_trait::async_trait;
use scorchkit::prelude::*;

#[derive(Debug)]
struct PoweredByVersion;

#[async_trait]
impl ScanModule for PoweredByVersion {
    fn name(&self) -> &str { "X-Powered-By version" }
    fn id(&self) -> &str { "powered-by-version" }
    fn category(&self) -> ModuleCategory { ModuleCategory::Scanner }
    fn description(&self) -> &str { "Find a version disclosed by X-Powered-By" }

    async fn run(&self, ctx: &ScanContext) -> Result<Vec<Finding>> {
        let response = ctx
            .http_client()
            .get(ctx.target.url.clone())
            .send()
            .await
            .map_err(|source| ScorchError::Http {
                url: ctx.target.url.to_string(),
                source,
            })?;

        let Some(value) = response
            .headers()
            .get("x-powered-by")
            .and_then(|header| header.to_str().ok())
        else {
            return Ok(Vec::new());
        };

        if !contains_version(value) {
            return Ok(Vec::new());
        }

        Ok(vec![Finding::new(
            self.id(),
            Severity::Low,
            "X-Powered-By discloses a runtime version",
            "The response identifies a runtime and version.",
            ctx.target.url.as_str(),
        )
        .with_evidence(format!("X-Powered-By: {value}"))
        .with_remediation("Remove the X-Powered-By header at the application or proxy.")
        .with_cwe(200)
        .with_confidence(0.9)])
    }
}

fn contains_version(value: &str) -> bool {
    value.contains('.') && value.chars().any(|character| character.is_ascii_digit())
}
```

Return an empty vector when the module ran and found nothing. Return an error when the module could
not complete its check. Do not turn timeouts, policy denials, missing tools, or parse failures into
findings.

## Register the module

Production contexts come from `Engine`; their constructors are intentionally private. Create an
engine with an explicit engagement, ask it for a context, then add the module to an orchestrator:

```rust,no_run
use std::sync::Arc;

use scorchkit::config::AppConfig;
use scorchkit::engine::policy::{Capability, EffectClass, Engagement, EngagementPolicy};
use scorchkit::engine::scope::ScopeRule;
use scorchkit::facade::Engine;
use scorchkit::runner::orchestrator::Orchestrator;

# use async_trait::async_trait;
# use scorchkit::prelude::*;
# #[derive(Debug)] struct PoweredByVersion;
# #[async_trait] impl ScanModule for PoweredByVersion {
# fn name(&self) -> &str { "fixture" }
# fn id(&self) -> &str { "powered-by-version" }
# fn category(&self) -> ModuleCategory { ModuleCategory::Scanner }
# fn description(&self) -> &str { "fixture" }
# async fn run(&self, _ctx: &ScanContext) -> Result<Vec<Finding>> { Ok(Vec::new()) }
# }
# async fn example() -> scorchkit::Result<()> {
let policy = EngagementPolicy::default()
    .allow_scope(ScopeRule::parse("127.0.0.1").expect("loopback scope"))
    .allow_capability(Capability::DastScan)
    .allow_effect(EffectClass::ActiveSafe);
let engine = Engine::for_engagement(
    Arc::new(AppConfig::default()),
    Arc::new(Engagement::new("local extension test", policy)),
);
let context = engine.dast_context("http://127.0.0.1:8080", "quick")?;
let mut runner = Orchestrator::new(context);
runner.add_module(Box::new(PoweredByVersion));
let result = runner.run(true).await?;
# let _ = result;
# Ok(())
# }
```

Call `register_default_modules()` before `add_module()` when the custom module should run with the
built-in registry. `CodeOrchestrator`, `InfraOrchestrator`, and `CloudOrchestrator` use the same
`add_module` pattern.

## Keep effects inside the context

- Use `ScanContext::http_client()` for target HTTP.
- Use `ScanContext::run_tool` or `run_tool_lenient` for a bounded external program.
- Keep SAST file access under the canonical `CodeContext::path`.
- Do not create a raw HTTP client, resolver, socket, subprocess, credential loader, or temporary
  directory inside a module. Add a reviewed context-owned seam when a required effect is missing.
- Keep scanner evidence separate from agent analysis.

## Test the extension

Cover metadata, clean input, positive input, parsing failures, and bounds. Network tests use a
loopback server and a matching engagement. Tool-backed tests inject an executor and assert the
program, arguments, timeout, output limit, and exit policy.

The two shipped examples are executable compatibility checks:

```bash
cargo test --manifest-path examples/custom_scanner/Cargo.toml
cargo test --manifest-path examples/custom_code_scanner/Cargo.toml
```

For an in-tree module, add it to the appropriate registry, update the module documentation, and add
or update the source-backed registry census.

Next: [extend a CVE backend](07-extending-cve-backends.md).
