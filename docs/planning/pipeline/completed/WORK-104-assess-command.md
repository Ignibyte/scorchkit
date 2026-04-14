# Work Pipeline: Unified `assess` Command — DAST + SAST + Infra

| Field | Value |
|-------|-------|
| **Pipeline Type** | Work |
| **Work Type** | Infrastructure |
| **Status** | COMPLETE |
| **Forge Ticket** | #104 |
| **Forge Ticket ID** | 019d8d98-24bc-7095-b364-4956b79fc815 |

---

## Phase 1: Plan — PASS

**Title:** Unified `assess` command — DAST + SAST + Infra composition.

**Scope:** Add `scorchkit assess [--url <url>] [--code <path>] [--infra <target>]` subcommand (feature-gated on `infra`). Runs the three orchestrators concurrently via `tokio::join!` and merges results through the existing `ScanResult::merge`. Any domain failing is non-fatal — partial results come back. Adds `Engine::full_assessment` facade method mirroring the CLI.

**Files:**
- MODIFY `src/cli/args.rs` — gated `Commands::Assess { url, code, infra, profile }` variant
- MODIFY `src/cli/runner.rs` — gated dispatch + `run_assess` function body
- MODIFY `src/facade.rs` — gated `Engine::full_assessment(url, code_path, infra_target)` method
- MODIFY `tests/cli.rs` — gated `test_cli_assess_help` integration test

**Dependencies:** WORK-101 (infra foundation). `ScanResult::merge` already exists (from WORK-091).

**Risks:**
- At-least-one-flag validation must live in the handler (clap's `ArgGroup` works but adds complexity; simple runtime check is clearer).
- Three-way target type mismatch: DAST parses URL, SAST uses path, Infra uses target string. Each constructor handles its own domain — no cross-domain validation.

**Acceptance:**
- `scorchkit assess --url https://example.com --code ./src --infra 127.0.0.1` runs all three concurrently.
- Any single flag alone also works; zero flags is an error.
- Any orchestrator failing is logged but doesn't abort the others — the returned ScanResult contains whatever completed.
- `Engine::full_assessment` parallels the CLI behavior.
- `cargo fmt / clippy / test --features infra / deny` all green.
- 2+ new tests (CLI help + facade doctest).

---

## Phase 2: Design — PASS

### Approach

Thin composition layer: the three orchestrators already exist and return `ScanResult`. `assess` just wires them concurrently and uses `ScanResult::merge` to combine outputs, picking the first non-error as the base (priority: DAST > SAST > Infra, matching the existing `full_scan` precedent).

Priority rationale: the first result's `Target` becomes the canonical `target` field on the merged `ScanResult` (because `merge` doesn't change the receiver's target). Users running all three likely care most about the URL-target context for reporting — DAST first preserves that. If only SAST + Infra are provided, SAST wins. If only Infra, Infra wins.

### Type changes

```rust
// src/cli/args.rs (gated)
#[cfg(feature = "infra")]
Assess {
    #[arg(long)]
    url: Option<String>,

    #[arg(long)]
    code: Option<PathBuf>,

    #[arg(long)]
    infra: Option<String>,

    #[arg(long, default_value = "standard")]
    profile: String,

    #[arg(long)]
    quiet: bool,
},

// src/facade.rs (gated)
impl Engine {
    #[cfg(feature = "infra")]
    pub async fn full_assessment(
        &self,
        url: Option<&str>,
        code_path: Option<&Path>,
        infra_target: Option<&str>,
    ) -> Result<ScanResult>;
}
```

### Runtime behavior

1. Parse flags; error if all three are `None`.
2. Build futures for each provided input.
3. `tokio::join!` them (unused slots are `async { Ok(None) }`).
4. Collect results; use the first Ok in priority order as the base, merge the other Oks into it.
5. Error cases: log at warn and skip that domain's results.
6. Return the merged `ScanResult`.

### Regression Test Plan

| # | Test | File | Verifies |
|---|------|------|----------|
| 1 | `test_cli_assess_help` | `tests/cli.rs` | Gated help output contains `url`/`code`/`infra` |
| 2 | `test_engine_full_assessment_doctest` | `src/facade.rs` | `no_run` doctest compiles |

CLI execution tests would require running real scans — skipped; smoke test is sufficient for the composition layer.

---

## Phase 3: Implement — PASS

### Files Modified
- `src/cli/args.rs` — gated `Commands::Assess { url, code, infra, profile, quiet }` variant.
- `src/cli/runner.rs` — gated dispatch arm + `run_assess` function body (validates at-least-one-flag, delegates to facade).
- `src/facade.rs` — gated `Engine::full_assessment(url, code_path, infra_target) -> Result<ScanResult>` with `no_run` doctest. Added private `absorb_outcome` helper so the merge-orchestration logic stays clippy-clean without `#[allow]` shenanigans.
- `tests/cli.rs` — gated `test_cli_assess_help` integration test.

### Quality Gates
- `cargo fmt --check`: PASS
- `cargo clippy -- -D warnings` (default): PASS
- `cargo clippy --features infra -- -D warnings`: PASS (1 fix iteration — `tuple_array_conversions` on `[dast, sast, infra]`; fixed by extracting `absorb_outcome` helper)
- `cargo test`: 506 (unchanged from WORK-103 — no changes to default build)
- `cargo test --features infra`: **541** passed + 1 new CLI integration test = 541 total, 0 failed
- `cargo deny check`: PASS

### Notes
- The `profile` CLI flag is accepted but currently ignored by `run_assess` (underscored). Full per-domain profile tuning is a later pipeline; for v1 the unified command uses default profiles for each domain. Users needing per-domain profiles call `run` / `code` / `infra` directly.
- `tracing::warn!` logs domain failures; the caller sees only the merged result (if any completed) or the first error.
- `absorb_outcome` helper makes the three-way merge composable without tuple/array lint noise.

---

## Phase 4: Validate — PASS

All gates re-run green. No new `#[allow]`, no `#[ignore]`, no ``` ```ignore ```.

- Three-way composition semantics match the existing `Engine::full_scan` DAST+SAST precedent — same priority ordering, same log-and-skip failure handling.
- `absorb_outcome` is private (pipeline-internal helper) but still docstring'd for maintainability.
- No `ScorchError` variants added; existing `Config` variant carries the "no inputs" error.
- Doctest on `Engine::full_assessment` compiles.

---

## Phase 5: Verify — PASS

541 / 0 under `--features infra`, 506 / 0 default. Zero regressions. `test_cli_assess_help` passes.

---

## Phase 6: Complete — PASS

### Documentation
- CHANGELOG entry for #104.
- Architecture decision `cli.assess-command` recorded.
- Engine architecture doc already references WORK-105 as the unified assess command — this pipeline ships #104 (the pipeline id bumped one slot; WORK-105/106 roadmap items shift).

### Self-Reflection
1. **Workarounds?** None. The `tuple_array_conversions` lint fix was a genuine refactor into a helper function, not a suppression.
2. **Cleanest version?** Yes for v1. Per-domain profile tuning deferred honestly; callers who need it use the single-domain commands.
3. **Senior dev approval?** Thin composition layer over three existing facade methods, `tokio::join!` for concurrency, `Option<Result<_>>` futures so skipped domains don't contribute to the outcome, `warn!`-and-continue failure semantics matching the existing `full_scan` precedent.

### Final Checklist
- [x] Phases 1-5 PASS
- [x] fmt / clippy / test / deny green (both feature sets)
- [x] bootstrap + recall + learn + architecture-set + save-generation-trace called
- [x] CHANGELOG updated
- [x] Pipeline archived
- [x] Ticket #104 closed
