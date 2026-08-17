# Unified assessment

`scorchkit assess` composes any requested subset of DAST, SAST, infrastructure, and cloud scans and
merges successful results into one `ScanResult`.

```bash
scorchkit assess \
  --url https://owned.example \
  --code ./src \
  --infra 192.0.2.10 \
  --cloud aws:123456789012 \
  --profile quick
```

The command is feature-gated by the requested families. At least one target is required.

## Composition

`Engine::full_assessment_with_profile` creates each family context independently, applies the same
named profile to each orchestrator, and then runs them. `Engine::full_assessment` remains a
compatibility helper that selects `thorough`. Every provided target must be covered by the same
engagement:

- the URL requires web scope and DAST/profile grants;
- the canonical code path requires a path-prefix rule plus `code-scan/passive` and external-tool
  capability for the current SAST registry;
- the infrastructure target requires network scope plus `infra-scan/active-safe` and external-tool;
- the cloud target requires an exact cloud rule plus `cloud-scan/passive`, credential-use, and
  external-tool.

One denied family returns its policy error. Authorization is completed before that family's effectful
resource is constructed.

## Runtime behavior

Provided families run concurrently with `tokio::join!`. Outcomes are absorbed in DAST, SAST,
infrastructure, then cloud order. The first successful result becomes the base; later successes merge
findings and module outcomes and recompute the summary.

Partial success is retained. If every requested family fails, the first error is returned. No-target
input is a configuration error.

| Scenario | Result |
|---|---|
| All requested families succeed | one merged result |
| One family fails and another succeeds | merged successful evidence plus a warning for the failure |
| Only requested family fails | error |
| Every requested family fails | first error |
| No family requested | configuration error |

## Library example

```rust
use std::path::Path;
use std::sync::Arc;
use scorchkit::config::AppConfig;
use scorchkit::engine::policy::{Capability, EffectClass, Engagement, EngagementPolicy};
use scorchkit::engine::scope::ScopeRule;
use scorchkit::facade::Engine;

# async fn example() -> scorchkit::engine::error::Result<()> {
let code_root = Path::new("./src").canonicalize()?;
let policy = EngagementPolicy::default()
    .allow_scope(ScopeRule::parse("owned.example").expect("web scope"))
    .allow_scope(ScopeRule::path_prefix(&code_root)?)
    .allow_scope(ScopeRule::parse("192.0.2.10").expect("network scope"))
    .allow_capability(Capability::DastScan)
    .allow_capability(Capability::CodeScan)
    .allow_capability(Capability::InfraScan)
    .allow_capability(Capability::ExternalTool)
    .allow_effect(EffectClass::Passive)
    .allow_effect(EffectClass::ActiveSafe);
let engine = Engine::for_engagement(
    Arc::new(AppConfig::default()),
    Arc::new(Engagement::new("authorized local assessment", policy)),
);

let result = engine
    .full_assessment_with_profile(
        Some("https://owned.example"),
        Some(&code_root),
        Some("192.0.2.10"),
        None,
        "quick",
    )
    .await?;
println!("{} findings", result.findings.len());
# Ok(())
# }
```

Use only targets included in the actual authorization. The documentation addresses are examples, not
permission to scan them.

## Downstream consumers

Terminal, JSON, HTML, SARIF, and PDF reporters consume the merged result. Project persistence stores
one assessment record with all module IDs. AI analysis receives the merged evidence as one labeled
input and remains non-authoritative.
