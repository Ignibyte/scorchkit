# 06 — Extending with custom modules

**Goal:** implement a new `ScanModule` from scratch. Use the existing `examples/custom_scanner` as your starting point.

**Time:** ~45 minutes for the basic walkthrough.

**You'll need:** Rust 1.70+. ScorchKit cloned. Comfort reading async Rust.

---

## 1. The trait

Every DAST module implements `ScanModule`:

```rust
#[async_trait]
pub trait ScanModule: Send + Sync {
    fn name(&self) -> &'static str;
    fn id(&self) -> &'static str;
    fn category(&self) -> ModuleCategory;
    fn description(&self) -> &'static str;

    async fn run(&self, ctx: &ScanContext) -> Result<Vec<Finding>>;

    // Optional — defaults provided
    fn requires_external_tool(&self) -> bool { false }
    fn required_tool(&self) -> Option<&str> { None }
}
```

For SAST, swap in `CodeModule` + `CodeContext`. For Infra, `InfraModule` + `InfraContext` (gated `--features infra`).

## 2. The example crate

`examples/custom_scanner/` is a separate cargo crate that depends on `scorchkit` as a library. It implements `DebugMarkerScanner`, a minimal scanner that flags any response body containing the word "debug". A sibling crate, `examples/custom_code_scanner/`, shows the same shape for SAST via the `CodeModule` trait.

Read it first:

```bash
cat examples/custom_scanner/src/lib.rs
```

The shape:

```rust
use async_trait::async_trait;
use scorchkit::prelude::*;

#[derive(Debug, Default)]
pub struct DebugMarkerScanner;

#[async_trait]
impl ScanModule for DebugMarkerScanner {
    fn name(&self) -> &'static str { "Debug Marker Scanner" }
    fn id(&self) -> &'static str { "debug-marker" }
    fn category(&self) -> ModuleCategory { ModuleCategory::Scanner }
    fn description(&self) -> &'static str {
        "Example plugin: flags responses containing the word 'debug'"
    }

    async fn run(&self, ctx: &ScanContext) -> Result<Vec<Finding>> {
        let body = ctx.http_client
            .get(ctx.target.url.as_str())
            .send().await
            .map_err(|e| ScorchError::Config(format!("request failed: {e}")))?
            .text().await
            .map_err(|e| ScorchError::Config(format!("body read failed: {e}")))?;

        if !body.to_lowercase().contains("debug") {
            return Ok(Vec::new());
        }
        Ok(vec![Finding::new(
            "debug-marker",
            Severity::Low,
            "Debug marker detected in response",
            "Response body contains the word 'debug'.",
            ctx.target.url.as_str(),
        ).with_confidence(0.6)])
    }
}
```

The crate is a library only — there's no `demo_scan` binary. To exercise it, either build the library and the module's unit tests (`cargo test -p custom_scanner`), or wire it into your own binary crate that constructs an `Orchestrator` and registers it (see §4 below).

## 3. Build your own

Let's make a real one. We'll write a module that flags any HTTP response whose `X-Powered-By` header reveals a runtime version.

### Skeleton

```rust
use async_trait::async_trait;
use scorchkit::prelude::*;
use scorchkit::engine::error::Result;
use scorchkit::engine::module_trait::{ModuleCategory, ScanModule};
use scorchkit::engine::scan_context::ScanContext;

pub struct PoweredByVersionLeak;

#[async_trait]
impl ScanModule for PoweredByVersionLeak {
    fn name(&self) -> &'static str { "X-Powered-By Version Leak" }
    fn id(&self) -> &'static str { "powered_by_leak" }
    fn category(&self) -> ModuleCategory { ModuleCategory::Scanner }
    fn description(&self) -> &'static str {
        "Detects X-Powered-By headers that disclose runtime version info"
    }

    async fn run(&self, ctx: &ScanContext) -> Result<Vec<Finding>> {
        let resp = ctx.http_client
            .get(ctx.target.url.as_str())
            .send()
            .await
            .map_err(|e| scorchkit::ScorchError::Http {
                url: ctx.target.url.to_string(),
                source: e,
            })?;

        let header = resp.headers()
            .get("x-powered-by")
            .and_then(|h| h.to_str().ok())
            .map(str::to_string);

        let Some(value) = header else {
            return Ok(Vec::new());
        };

        if !contains_version(&value) {
            return Ok(Vec::new());
        }

        Ok(vec![Finding::new(
            "powered_by_leak",
            Severity::Low,
            "X-Powered-By header discloses runtime version",
            format!("Header: X-Powered-By: {value}"),
            ctx.target.url.as_str(),
        )
        .with_evidence(format!("X-Powered-By: {value}"))
        .with_remediation("Remove the X-Powered-By header in your reverse proxy / app server config.")
        .with_owasp("A05:2021 Security Misconfiguration")
        .with_cwe(200)
        .with_confidence(0.9)])
    }
}

/// Pure helper — easy to unit test.
fn contains_version(header_value: &str) -> bool {
    header_value.chars().any(|c| c.is_ascii_digit())
        && header_value.contains('.')
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn detects_version_in_header() {
        assert!(contains_version("PHP/8.1.0"));
        assert!(contains_version("Express 4.17"));
        assert!(!contains_version("PHP"));
        assert!(!contains_version(""));
    }
}
```

### Pattern notes

- **Pure helpers are the load-bearing testable units.** `contains_version` has no async, no I/O, no context — just `&str → bool`. Cover it with unit tests; the `run` method then delegates.
- **Error handling.** `?` over `ScorchError`. Return `Ok(Vec::new())` for "no findings" — never `Err`. `Err` means infrastructure failure (network down, parse failed); the orchestrator logs it and continues with other modules.
- **`Finding::new(...)` builder.** Always specify module_id, severity, title, description, affected. Add evidence, remediation, OWASP/CWE, confidence via `.with_*()` methods.
- **`Severity::Info` is for observations, not bugs.** Discovered something interesting that isn't itself a defect? Use Info.

## 4. Wire it into the project

If you're upstreaming the module:

1. Drop the file at `src/scanner/powered_by_leak.rs` (or `src/recon/...` if it's recon-style).
2. Register it in the appropriate `mod.rs`:
   ```rust
   pub mod powered_by_leak;
   ```
3. Add to `register_modules()`:
   ```rust
   Box::new(powered_by_leak::PoweredByVersionLeak),
   ```
4. Add a doc at `docs/modules/powered-by-leak.md`.
5. Open a PR.

If it's a one-off for your own use, keep it in a separate crate that depends on `scorchkit` (the way `examples/custom_scanner` does). At the moment, `Orchestrator` (DAST) only exposes `register_default_modules` + filter APIs — not a public `add_module` — so the cleanest path for out-of-tree use is to drive your module directly from your own binary:

```rust
let ctx = ScanContext::new(target, http_client, config);
let module = PoweredByVersionLeak;
let findings = module.run(&ctx).await?;
```

If you need full orchestration (concurrency, progress, result aggregation) for an out-of-tree module, the `InfraOrchestrator` does expose `add_module` — or upstream the module via the steps above. Tracking a public `Orchestrator::add_module` extension point is a known gap.

## 5. Constraints to respect

- **No `unwrap()` / `expect()` in production code.** Project clippy denies them. Use `?`, `let-else`, `ok_or`, `is_ok_and`.
- **Async, not threads.** Tokio runtime is already running; spawn tasks via `tokio::spawn` if you need concurrency.
- **Respect the proxy and TLS config.** Use `ctx.http_client` rather than building your own — it's already configured with the operator's proxy, auth, TLS, cookie jar settings.
- **Don't burn the rate budget.** If your module makes many HTTP calls, throttle yourself or document the cost in the module description.

## 6. Where to go next

- **[07 — Extending CVE backends](07-extending-cve-backends.md)** — same shape, but for `CveLookup` impls
- The `engine::` module — read it for the canonical types every module touches

---

## Things that go wrong

| Symptom | Cause | Fix |
|---------|-------|-----|
| `cargo build` fails on your custom crate with "trait method not found" | Imported the wrong `ScanModule` (e.g. trait moved between minor versions) | `cargo doc --open --package scorchkit` to confirm the API; pin to a specific scorchkit version in your Cargo.toml |
| Your module never runs in the orchestrator | Forgot to register it in `register_modules()` | Add `Box::new(YourModule)` to the vec |
| Findings show with `module_id = "?"` | Used a different string in `id()` and `Finding::new(...)` | Make them match — convention is to use the same const string |
