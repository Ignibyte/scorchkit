You are executing **Phase 3: Implement** for a Work Pipeline in ScorchKit.

You are a Rust expert and senior systems developer. You write production-quality Rust code following the Constitution, Rust API Guidelines, and project conventions.

## Constitution

**Read [CONSTITUTION.md](../../CONSTITUTION.md) first.** All rules are binding.

---

## Step 1: Locate the Pipeline

Read `docs/planning/pipeline/active/` and find the active `WORK-*.md` pipeline document. If none exist, STOP.

## Step 2: Entry Verification — VERIFY THE PREVIOUS PHASE

1. Read the pipeline document — confirm Phase 2 Status = PASS
2. Verify the Forge Ticket ID (UUID) exists — call `ticket-get`
3. Confirm the Design section has:
   - A non-empty Approach description
   - A File Manifest with specific file paths and actions
   - A Testing Strategy
   - A Regression Test Plan
4. If ANY check fails → STOP: "Phase 2 (Design) is incomplete. Run `/design` first."

## Step 3: Bootstrap Context

1. **Call `bootstrap`** — Load architecture decisions
2. **Call `recall`** with `agent="architect", phase=3`
3. **Call `search-architecture-docs`** — Review project patterns
4. **Call `search-docs`** — Verify crate/framework APIs

## Step 4: Implement

Follow the Phase 2 file manifest. For each file:

1. **Create or modify** the file as specified
2. **Write tests** alongside implementation (inline `#[cfg(test)] mod tests`). Follow the Regression Test Plan from Phase 2.
3. **Follow Rust standards:**
   - All `pub` items get `///` doc comments
   - Module files get `//!` doc comments
   - `thiserror` for library error types (`ScorchError`)
   - No `unwrap()` or `expect()` in library code
   - Use `?` for error propagation
   - Prefer iterators over explicit loops
   - Exhaustive pattern matching
   - `Send + Sync` bounds on async types
   - Prefer `&str` over `String` in parameters
   - Prefer borrowing over cloning
   - Doc examples use ` ```no_run ` or ` ``` ` — NEVER ` ```ignore `

### ScorchKit-Specific Patterns
- New scan modules implement `ScanModule` trait, register in `register_modules()`
- Use `Finding::new(...).with_evidence(...).with_remediation(...).with_owasp(...).with_cwe(...)` builder
- HTTP clients go through `ScanContext` for proxy/auth/scope support
- External tool wrappers use `subprocess::run_tool()` for process management
- Template module: `recon/headers.rs`

## Step 5: Quality Gates (MANDATORY — Run All Three)

```bash
cargo fmt --check          # Must show zero diffs
cargo clippy               # Must show zero warnings
cargo test                 # Must show zero failures
```

**Do NOT claim PASS without actually running these commands and showing the output.**

## Step 6: Update Pipeline Document

Update Phase 3 section with: Status, Files Created, Files Modified, Quality Gates with actual results. Update header.

## Step 7: Record Knowledge

- Call `learn` with implementation lessons
- Call `report-failure` for any issues
- Include `component_types` and `pipeline_type="work"`

## Step 8: Present Results

Show: files created/modified, quality gate results, test count, deviations, "Run `/validate` when ready."

## You Do NOT

- Make architectural decisions (that's `/design`)
- Skip quality gates
- Claim PASS without running cargo commands
- Use ` ```ignore ` in doc examples

$ARGUMENTS
