# Trusted Rust module extension API

ScorchKit exposes Rust traits for trusted in-process DAST and SAST modules. An extension receives a
policy-sealed context and returns normal `Finding` values, so it can share orchestration, events,
reports, and error handling with built-in modules.

This is a source-level Rust API, not a stable binary plugin ABI or a sandbox. Loading a Rust module
means trusting its code with the host process. For digest-bound third-party code, use the separate
[isolated WebAssembly extension runtime](architecture/extensions.md).

## Choose a module type

| Trait | Context | Use |
|---|---|---|
| `ScanModule` | `ScanContext` | URL-based DAST and reconnaissance |
| `CodeModule` | `CodeContext` | local static analysis and dependency checks |
| `InfraModule` | `InfraContext` | host, address, protocol, and network checks |
| `CloudModule` | `CloudContext` | cloud posture checks |

Infrastructure and cloud traits require their Cargo features. The examples below cover the public
DAST and SAST integration paths.

## DAST module

Use `ScanContext::http_client()` for target HTTP. The returned client already carries the
engagement-aware DNS resolver and redirect policy plus configured authentication, proxy, cookie,
TLS, user-agent, and timeout settings.

```rust,no_run
use async_trait::async_trait;
use scorchkit::prelude::*;

#[derive(Debug)]
struct DebugMarker;

#[async_trait]
impl ScanModule for DebugMarker {
    fn name(&self) -> &str { "Debug marker" }
    fn id(&self) -> &str { "debug-marker" }
    fn category(&self) -> ModuleCategory { ModuleCategory::Scanner }
    fn description(&self) -> &str { "Find a debug marker in the target response" }

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
        let body = response.text().await.map_err(|source| ScorchError::Http {
            url: ctx.target.url.to_string(),
            source,
        })?;

        if !body.to_ascii_lowercase().contains("debug") {
            return Ok(Vec::new());
        }
        Ok(vec![
            Finding::new(
                self.id(),
                Severity::Low,
                "Debug marker in response",
                "The response contains a debug marker that may expose development behavior.",
                ctx.target.url.as_str(),
            )
            .with_evidence("case-insensitive response marker: debug")
            .with_remediation("Disable debug output in the deployed application.")
            .with_cwe(489)
            .with_confidence(0.6),
        ])
    }
}
```

A target method should use the context client or another explicit context seam. Constructing a new
HTTP client, resolver, raw socket, subprocess launcher, credential loader, or temporary path bypasses
shared controls and requires a reviewed ScorchKit architecture change.

## SAST module

`CodeContext::path` is canonicalized and authorized before the context is returned. Keep traversal
under that root and decide how symlinks are handled before reading them.

```rust,no_run
use async_trait::async_trait;
use scorchkit::prelude::*;

#[derive(Debug)]
struct ManifestPresence;

#[async_trait]
impl CodeModule for ManifestPresence {
    fn name(&self) -> &str { "Manifest presence" }
    fn id(&self) -> &str { "manifest-presence" }
    fn category(&self) -> CodeCategory { CodeCategory::Sca }
    fn description(&self) -> &str { "Report projects with no recognized root manifest" }

    async fn run(&self, ctx: &CodeContext) -> Result<Vec<Finding>> {
        if !ctx.manifests.is_empty() {
            return Ok(Vec::new());
        }
        Ok(vec![Finding::new(
            self.id(),
            Severity::Info,
            "No recognized root manifest",
            "ScorchKit did not find a supported dependency manifest at the scan root.",
            ctx.path.display().to_string(),
        )
        .with_confidence(1.0)])
    }
}
```

Return an empty language list for a language-neutral module. A nonempty `languages()` list lets the
code orchestrator filter it against the selected or detected language.

## Register a trusted module

Contexts come from `Engine`; direct constructors are intentionally not public.

```rust,no_run
use std::sync::Arc;

use scorchkit::config::AppConfig;
use scorchkit::engine::policy::{
    Capability, EffectClass, Engagement, EngagementPolicy,
};
use scorchkit::engine::scope::ScopeRule;
use scorchkit::facade::Engine;
use scorchkit::runner::orchestrator::Orchestrator;

# use async_trait::async_trait;
# use scorchkit::prelude::*;
# #[derive(Debug)] struct DebugMarker;
# #[async_trait] impl ScanModule for DebugMarker {
# fn name(&self) -> &str { "Debug marker" }
# fn id(&self) -> &str { "debug-marker" }
# fn category(&self) -> ModuleCategory { ModuleCategory::Scanner }
# fn description(&self) -> &str { "fixture" }
# async fn run(&self, _ctx: &ScanContext) -> Result<Vec<Finding>> { Ok(Vec::new()) }
# }
# async fn example() -> scorchkit::Result<()> {
let policy = EngagementPolicy::default()
    .allow_scope(ScopeRule::parse("127.0.0.1").expect("scope"))
    .allow_capability(Capability::DastScan)
    .allow_effect(EffectClass::ActiveSafe);
let engine = Engine::for_engagement(
    Arc::new(AppConfig::default()),
    Arc::new(Engagement::new("local extension test", policy)),
);
let context = engine.dast_context("http://127.0.0.1:8080", "quick")?;
let mut runner = Orchestrator::new(context);
runner.add_module(Box::new(DebugMarker));
let result = runner.run(true).await?;
# let _ = result;
# Ok(())
# }
```

Call `register_default_modules()` before `add_module()` when the extension should run alongside the
built-in registry. `CodeOrchestrator`, `InfraOrchestrator`, and `CloudOrchestrator` expose the same
`add_module` pattern.

## Finding contract

```rust
use scorchkit::prelude::*;

let finding = Finding::new(
    "module-id",
    Severity::High,
    "Specific observed issue",
    "What was observed and why it matters.",
    "affected target",
)
.with_evidence("raw or normalized proof")
.with_remediation("specific corrective action")
.with_owasp("A03:2021 Injection")
.with_cwe(89)
.with_confidence(0.9);
# let _ = finding;
```

Module IDs are stable, short, and user-facing. Confidence is evidence strength, not severity. Keep
raw observations in evidence and do not present agent inference as scanner proof.

## Errors and failure behavior

Return `Result<Vec<Finding>>`. Empty findings mean the module ran and observed no issue. An error
means the module could not complete its contract. The orchestrator records the module error, marks it
skipped, and continues independent modules.

Do not turn a timeout, parser error, missing executable, policy denial, or connection failure into a
positive finding. Preserve the typed error where possible.

## External-tool definitions

The TOML plugin loader in `runner::plugin` supports declarative wrappers around external programs.
Those wrappers still execute through `ScanContext::run_tool`, so target and `ExternalTool` grants,
canonical executable resolution, timeout, output caps, exit policy, and process-tree cleanup remain
active. Plugin definitions are trusted configuration and should be reviewed like code.

## Verification

The repository ships two trusted Rust examples and one isolated WebAssembly example:

- `examples/custom_scanner`
- `examples/custom_code_scanner`
- `examples/custom_wasm_extension`

Compile and test them against the current checkout:

```bash
cargo test --manifest-path examples/custom_scanner/Cargo.toml
cargo test --manifest-path examples/custom_code_scanner/Cargo.toml
cargo build --manifest-path examples/custom_wasm_extension/Cargo.toml \
  --target wasm32-unknown-unknown
```

Module tests should cover metadata, clean input, positive input, parser failures, bounds, and the
declared effect path. Network integration tests use loopback servers. External-tool modules should
use an injected executor and assert the exact program, arguments, timeout, exit policy, and output
limit.
