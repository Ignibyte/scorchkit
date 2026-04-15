# Unified Assess Command

`scorchkit assess` composes the three module families into a single invocation. It is the operator-facing expression of v2.1's three-pillar architecture: any combination of DAST, SAST, and Infra runs concurrently and merges into one `ScanResult`.

```
scorchkit assess [--url <url>] [--code <path>] [--infra <target>]
```

At least one flag is required. Any subset works — a DAST-only assessment is equivalent to `scorchkit run`; a DAST + SAST assessment matches `scorchkit run --code`; the full three-way form is the new capability.

The subcommand is feature-gated on `#[cfg(feature = "infra")]` — enable with `cargo build --features infra`.

## Architecture Decision

**Decision:** Compose at the facade layer via `tokio::join!` of three independent orchestrator runs, then merge results. Do not extend any single orchestrator to know about the others.

**Rationale:** Each orchestrator already provides the right abstraction for its domain — DAST runs web probes, SAST runs code analyzers, Infra runs network probes. Composition at `Engine::full_assessment` keeps each orchestrator single-purpose, lets the three domains fail independently, and gives library consumers the same capability surface as the CLI.

## Facade Method

```rust
// src/facade.rs
#[cfg(feature = "infra")]
pub async fn full_assessment(
    &self,
    url: Option<&str>,
    code_path: Option<&Path>,
    infra_target: Option<&str>,
) -> Result<ScanResult>;
```

Behavior:

1. **Validate inputs.** If all three are `None`, return `ScorchError::Config`.
2. **Dispatch concurrently.** Each provided domain becomes a tokio future that calls the corresponding single-domain facade method (`self.scan`, `self.code_scan`, `self.infra_scan`). Each future yields `Option<Result<ScanResult>>` — `None` means the domain wasn't requested, `Some(Ok(r))` means it succeeded, `Some(Err(e))` means it failed.
3. **Drive all three with `tokio::join!`.** The three futures run in parallel within the same task scope; no spawning, no select loop.
4. **Absorb outcomes.** The private helper `absorb_outcome` folds each `Option<Result<ScanResult>>` into the assembling base in **DAST → SAST → Infra priority order**:
   - First `Ok` becomes the base `ScanResult`.
   - Subsequent `Ok`s merge into the base via `ScanResult::merge(other)`.
   - Every `Err` is logged at `warn` with the failed domain; the first one is retained as `first_err` for the fallback error path.
5. **Return.** If any domain succeeded, the base is returned (partial results are the happy path when one domain fails). If every provided domain failed, the first error is returned. If nothing succeeded *and* nothing failed (impossible given the validation in step 1), a `ScorchError::Config("assess: no results")` fallback fires.

The priority order matches `Engine::full_scan`'s precedent — DAST is the primary record, SAST and Infra findings are merged in. The receiving base keeps its `scan_id`, `started_at`, and target; `ScanResult::merge` concatenates `findings`, extends `modules_run` and `modules_skipped`, and recomputes `summary`.

## Per-Domain Failure Handling

Partial results are first-class. The design intent is that a CI pipeline running `scorchkit assess` against a new environment shouldn't fail just because, say, the infra target isn't reachable yet or the SAST tools aren't installed on the runner.

| Scenario | Behavior |
|----------|----------|
| All three succeed | Merged `ScanResult` with findings from every domain |
| DAST fails, SAST + Infra succeed | SAST becomes base; Infra merged in; `warn!` logged for DAST |
| Only one domain requested and it fails | Error returned — operator asked for exactly that one thing |
| All provided domains fail | First error returned; operator sees a real failure, not silent zero-findings |
| No domain provided | `ScorchError::Config` from step 1 |

Individual domain successes are never withheld to punish a sibling failure.

## CLI Surface

```
# DAST + SAST + Infra
scorchkit assess \
    --url https://example.com \
    --code ./src \
    --infra 10.0.0.0/24

# DAST + Infra only
scorchkit assess --url https://example.com --infra example.com

# SAST + Infra only (no running target yet)
scorchkit assess --code ./src --infra 10.0.0.0/24
```

All standard report/storage flags (`--format`, `--output`, `--project`, ...) apply to the merged `ScanResult` — operators get one report covering every domain, not three separate reports.

## Library Example

```rust
use std::path::Path;
use std::sync::Arc;
use scorchkit::facade::Engine;
use scorchkit::config::AppConfig;

# async fn example() -> scorchkit::engine::error::Result<()> {
let engine = Engine::new(Arc::new(AppConfig::default()));
let result = engine
    .full_assessment(
        Some("https://example.com"),
        Some(Path::new("./src")),
        Some("127.0.0.1"),
    )
    .await?;
println!("unified findings: {}", result.findings.len());
# Ok(())
# }
```

## Interaction with AI and Storage

The merged `ScanResult` flows into every downstream consumer unchanged:

- **Reports** — terminal, JSON, HTML, SARIF, PDF. All six formats already consume `ScanResult`; nothing is assess-specific.
- **Storage** — one scan row per assessment, one findings table, deduplication by fingerprint. The `modules_run` list includes modules from all three families; downstream queries see a unified view.
- **AI analysis** — `AiAnalyst::analyze` works on the merged result. Cross-domain correlation rules (see [sast.md §Cross-Domain Correlation](sast.md#cross-domain-correlation)) can now pair DAST + SAST findings *and* DAST + Infra findings in the same analysis pass. Extending correlations to SAST ↔ Infra pairs is a natural follow-up.

## See Also

- [overview.md](overview.md) — the three module families and the shared data flow
- [sast.md](sast.md) — the SAST pipeline
- [infra.md](infra.md) — the Infra pipeline
- [cve-backends.md](cve-backends.md) — CVE correlation backends (plug into the Infra domain)
