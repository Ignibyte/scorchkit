# Project Constitution

> Immutable rules that govern all phases, all sessions, all commands.
> No phase command may override, skip, or reinterpret these rules under any circumstances.

---

## 0. Quality Above All Else

- **Best-practice code is the only acceptable output.** Every phase must produce the cleanest, most idiomatic, most maintainable solution — not the fastest or cheapest one.
- **Never cut corners to save time or tokens.** The human does not care how long a task takes or how many iterations it requires. Thoroughness is not a cost — it is the standard.
- **Workarounds are technical debt.** If the correct solution exists, use it. If a workaround is unavoidable, flag it explicitly, record it as a lesson, and document why the proper approach was blocked.
- **Idiomatic Rust is non-negotiable.** Follow the [Rust API Guidelines](https://rust-lang.github.io/api-guidelines/), standard library conventions, and established ecosystem patterns. Code that compiles but violates Rust idioms is not done.
- **Prefer clarity over cleverness.** Readable, well-structured code that any Rust developer can maintain beats compact or "elegant" code that requires explanation. Favor explicit types over complex inference chains. Favor named structs over tuples for public APIs.

## 1. Crate Boundary

- **Dependencies declared in `Cargo.toml` are consumed, not vendored.** No phase may modify, fork, or patch dependency source code within this project. If a dependency needs changes, contribute upstream or wrap it.
- **No `[patch]` overrides to local paths in production.** Path dependencies are acceptable only for workspace members. Git or registry dependencies are the standard for external crates.
- All generated code targets: `src/`, `tests/`, `benches/`, `examples/`.

## 2. Pipeline by Default

- **All code changes go through a pipeline.** Any bug fix, feature, refactor, or infrastructure change — regardless of size — MUST use the appropriate pipeline. There are no exceptions unless the human explicitly says to skip the pipeline.
- **"It's a small fix" is not an excuse.** Small fixes still get a work pipeline. The pipeline ensures design review, testing, validation, and knowledge recording happen. Skipping the pipeline means skipping quality gates.
- **Only the human can waive the pipeline.** If the human explicitly says "no pipeline", "just do it", "skip the pipeline", or similar — then and only then may work proceed without a pipeline. Work may NOT be self-classified as "too small" for a pipeline.
- **`/work` decides the pipeline type.** Use the decision tree in the `/work` command. Module work = module pipeline. Everything else = work pipeline. Quick fixes that the human explicitly waives = direct implementation.

## 3. Phase Gates

- **Every phase has an entry gate.** The previous phase must be PASS before the next phase begins.
- **Broad directives are NOT permission to skip gates.** "Build the whole thing" still means phase-by-phase.
- **Human checkpoints are mandatory** between modules in multi-module pipelines.
- **NEVER have two pipeline documents active** for the same project simultaneously.
- **Deferred work is not done work.** Incomplete = BLOCKED, not PASS.

## 4. Phase Scope

Each phase command has a defined boundary. Crossing it is a constitutional violation. Enforced by `enforce-agent-scope.sh` which reads the current phase from the pipeline document.

| Phase | Command | Writes Code | Writes Docs | Makes Design Decisions | Runs Tests |
|-------|---------|:-----------:|:-----------:|:---------------------:|:----------:|
| 1 Plan | /work | NO | pipeline doc only | NO | NO |
| 2 Design | /design | NO | pipeline doc only | YES | NO |
| 3 Implement | /implement | YES | pipeline doc | NO | YES |
| 4 Validate | /validate | fix bugs only | pipeline doc | NO | YES |
| 5 Verify | /verify | NO | pipeline doc | NO | YES |
| 6 Complete | /complete | NO | docs + changelog | NO | NO |

## 5. Module Organization

- **Public API is defined in `lib.rs`.** All types, traits, and functions intended for external consumption must be re-exported from `lib.rs`. Internal modules remain private.
- **Module structure follows domain boundaries.** Group code by domain concept, not by technical layer. The `scanner/` module contains all vulnerability scanners. The `recon/` module contains all reconnaissance modules.
- **Re-exports in `lib.rs` define the public API surface.** If it is not re-exported, it is not public API — even if the item itself is `pub`.
- **No premature `pub` exposure.** Start with the most restrictive visibility (`pub(crate)`, `pub(super)`) and widen only when a consumer outside the module boundary needs access. Every `pub` item is a commitment.
- **Registration and wiring happen in designated locations.** Module registration in `register_modules()`, CLI dispatch in `cli/runner.rs`. Do not scatter wiring across arbitrary modules.

## 6. File Placement

| Component | Location |
|-----------|----------|
| Library root | `src/lib.rs` |
| Binary entry | `src/main.rs` |
| Core engine types | `src/engine/` |
| CLI interface | `src/cli/` |
| Configuration | `src/config/` |
| Scan orchestration | `src/runner/` |
| Reconnaissance modules | `src/recon/` |
| Vulnerability scanners | `src/scanner/` |
| External tool wrappers | `src/tools/` |
| AI integration | `src/ai/` |
| Report generation | `src/report/` |
| Integration tests | `tests/` |
| Benchmarks | `benches/` |
| Examples | `examples/` |

## 7. Testing Standards

- **Use `#[test]` for synchronous tests and `#[tokio::test]` for async tests.** Match the test attribute to the function signature.
- **Integration tests live in `tests/`.** Unit tests live in `#[cfg(test)] mod tests` blocks within the source file they test.
- Every test verifies one thing. AAA pattern: Arrange, Act, Assert.
- **No `unwrap()` in tests — use `?` with `anyhow::Result` or the crate's error type.** Test functions should return `Result<()>` so failures produce meaningful error messages, not panics.
- Use property-based testing with `proptest` when testing invariants across input ranges. Reserve example-based tests for specific edge cases and regression scenarios.
- Use test fixtures and builder patterns for complex setup. Mock external services with traits and test doubles.
- **NEVER mark PASS if tests didn't actually run.** Compilation errors = "Not Run", not PASS.
- Report actual test counts from `cargo test` output. Never estimate.
- **Test code MUST be fully documented.** This is the explicit opposite of the general "minimal comments" rule. Every test module and function must include: a `///` doc comment on the test module explaining what the test suite covers, a `///` doc comment on each test function explaining what is being tested, why it matters, and the expected behavior, and inline comments for non-obvious arrange/act/assert steps. Tests are living documentation.

## 8. Validation Standards

- **`cargo clippy` must pass with zero warnings.** All clippy lints at the default level must be clean. Project-configured lints (in `Cargo.toml`) are additionally enforced.
- **`cargo fmt --check` must pass.** All code must conform to the project's `rustfmt.toml` configuration, or the default `rustfmt` style if no configuration exists.
- **`cargo doc --no-deps` must build without warnings.** All public items must have documentation. Broken intra-doc links, missing examples, and undocumented public items are failures.
- **NEVER mark PASS if validation didn't actually run.**

## 9. Knowledge Recording

Before completing any phase, every phase command MUST:

### Step 1: Self-Reflection (MANDATORY)

Stop and honestly answer these three questions before recording knowledge:

1. **Did I use any workarounds instead of a proper solution?** — If something felt like a hack, a temporary fix, or a "good enough for now" approach, it must be flagged. Record it as a failure with the root cause of why the proper approach was blocked, and what the correct solution would be.
2. **Is my implementation the cleanest, most maintainable version of this solution?** — Review your own output critically. If there is a more idiomatic Rust pattern, a cleaner trait design, a better error handling strategy, or a more readable structure that you passed over, go back and fix it before handing off. Do not record "lesson learned" and move on — actually fix it.
3. **Would a senior Rust developer reviewing this code approve it without changes?** — If the answer is no, identify what they would flag and address it now. If you cannot address it (blocked by a dependency, ecosystem limitation, or scope constraint), record it explicitly as a lesson with the specific improvement that should be made.

### Additional Rust-Specific Reflection

4. **Did I use any `unsafe` blocks that could be avoided?** — If `unsafe` was used, verify that a safe alternative does not exist. If `unsafe` is genuinely required, ensure the `// SAFETY:` comment fully documents the invariants that must hold.
5. **Are my error types expressive and actionable?** — Callers should be able to match on error variants and take meaningful recovery action. Generic string errors or opaque error types are not acceptable.
6. **Did I introduce any unnecessary allocations or clones?** — Review ownership patterns. Prefer borrowing over cloning. Use `Cow<'_, str>` when a function may or may not need to own its data.

### Step 2: Record Knowledge

1. **Call `learn`** — Record lessons with `source="pipeline-{command}-phase-{N}"`.
2. **Call `report-failure`** — Record any failures encountered.
3. **Call `save-generation-trace`** — `/complete` phase only (AAR).

Knowledge must include `component_types` array detected from file paths.
For work pipelines: include `pipeline_type="work"` and `work_title`.

## 10. Pipeline Document Integrity

- **The pipeline document is the source of truth**, not conversational memory.
- Every phase command must update its phase section with complete details before finishing.
- Every phase must set Status to PASS, FAIL, or BLOCKED.
- Every phase must update the header (Status, Last Updated, Last Command, Next Step).
- **Context continuity check is mandatory** — always verify pipeline state before proceeding.

## 11. Recall Before Action

- **NEVER skip `recall`.** Every phase command calls `recall` with the appropriate agent name and pipeline phase before starting work.
- Prevention rules returned by recall are binding. They are not suggestions.
- **Note:** Golden examples may not exist for early projects. Recall still provides lessons, prevention rules, and failure patterns from the Forge knowledge base. Absence of golden examples does not excuse skipping recall.

## 12. Production Safety

- **No `unsafe` without documented safety invariants.** Every `unsafe` block requires a `// SAFETY:` comment that explains exactly which invariants the programmer is guaranteeing. "This is safe because I checked" is not sufficient — specify the concrete conditions.
- **No `unwrap()` or `expect()` in library code.** Use `Result<T, E>` with the `?` operator for fallible operations. `unwrap()` and `expect()` are acceptable only in tests, examples, and `main()` after all error handling has been exhausted.
- **Memory safety is guaranteed by the compiler — do not circumvent it.** Do not use `unsafe` to work around borrow checker errors. If the borrow checker rejects your code, redesign the data flow. The compiler is right.
- **Thread safety via `Send`/`Sync` bounds.** All types shared across threads must implement `Send` and/or `Sync` as appropriate. Do not use `unsafe impl Send` or `unsafe impl Sync` without documented justification.
- **No `std::process::exit()` in library code.** Libraries return errors; binaries decide whether to exit. Panics in library code should be reserved for genuinely unrecoverable states (violated invariants), not for error handling.
- **Resource cleanup via `Drop`.** All resources (file handles, network connections, subprocess handles) must implement `Drop` or use RAII wrappers that do. Do not rely on callers to manually close resources.

## 13. Uncertainty Handling

- **NEVER guess when uncertain.** Mark ambiguity explicitly with `[NEEDS CLARIFICATION]` in specs and blueprints.
- Return `CLARIFICATION_NEEDED` blocks for routing. Silent assumptions are constitutional violations.
- **Type system is your ally.** When uncertain about a value's possible states, encode the uncertainty in the type system (`Option<T>`, `Result<T, E>`, enums with explicit variants) rather than using sentinel values or comments.

## 14. Code Quality Standards

Every Rust file produced by any phase must meet these standards. No exceptions.

- **`///` doc comments are required on all public items** — types, functions, methods, trait definitions, constants, and enum variants. Every public item must explain its purpose, behavior, and any important invariants.
- **`//!` module-level documentation is required in every module file** — `mod.rs` or named module files. The module doc explains the module's role in the crate, its key types, and its relationship to other modules.
- **All public types must `#[derive(Debug)]` at minimum.** Types that represent data should also derive `Clone`, `PartialEq`, and `Eq` where semantically appropriate. Serializable types must derive `Serialize` and `Deserialize`.
- **Error types must implement `std::error::Error` and `std::fmt::Display`.** Use `thiserror` for library errors and `anyhow` for application-level error handling. Error variants must be specific and actionable — no catch-all `Other(String)` variants unless truly necessary.
- **No `unwrap()` or `expect()` in library code.** Use `Result<T, E>` with the `?` operator. The only exceptions are: (1) tests, (2) examples, (3) provably infallible operations where a comment explains why the value is always `Some`/`Ok`.
- **`unsafe` blocks require `// SAFETY:` comments** explaining the exact invariants the programmer guarantees. Every `unsafe` block must be as small as possible — extract safe wrappers around unsafe operations.
- **100% test coverage on new and modified code is required.** Coverage must be verified (via `cargo tarpaulin` or `cargo llvm-cov`) and reported. Coverage below 100% on new/modified files blocks the pipeline.
- **`cargo clippy` must pass with zero warnings** on all new and modified code. Do not suppress warnings with `#[allow(...)]` unless the suppression itself is documented with a comment explaining why the lint does not apply.
- **`cargo fmt --check` must pass.** All code must be formatted before finalizing any phase that produces Rust code. Run `cargo fmt` before committing.
- **All function signatures must have explicit return types.** Do not rely on implicit `()` return for non-trivial functions. If a function returns `()`, make it explicit when the function has side effects that callers should be aware of.
- **Lifetime annotations must be explicit when the compiler requires them.** Do not fight lifetime elision — but when lifetimes appear, name them descriptively (`'conn`, `'query`, `'ctx`) rather than using `'a`, `'b` for complex signatures.
- **No `clone()` to satisfy the borrow checker** unless the clone is semantically correct and the performance cost is acceptable. If you are cloning to work around a borrow conflict, redesign the data flow.

## 15. Enforcement and Anti-Circumvention

This section is enforced by hooks in `.claude/hooks/`. Hooks are automated gatekeepers — they run before tool calls (PreToolUse) and before session completion (Stop). No phase command may bypass, disable, or work around them.

### Transcript is the Source of Truth

- **If it didn't happen in the transcript, it didn't happen.** Claims of running tests, checking formatting, or calling MCP tools are not evidence. The hooks parse the actual session transcript for tool_use blocks. Only verified execution counts.
- **Writing test files without running them is not testing.** The enforce-tests-ran.sh hook verifies that test commands (`cargo test`) were actually executed via the Bash tool, not just that test files were created.
- **MCP calls must actually occur, not just be planned.** The enforce-completion.sh hook verifies that required MCP tools (bootstrap, recall, learn, search-architecture-docs, etc.) were called in the transcript. Stating "I will call bootstrap" without calling it is a violation.

### Scope Boundaries are Hard Walls

- **Phase write scope is enforced by enforce-agent-scope.sh.** Phase 1-2 may only write to `docs/`. Phase 3 has broad access. Phase 5 can write docs only. Phase 6 can write docs + changelog. These boundaries are not guidelines — they are hard blocks.
- **Documentation before code is enforced by enforce-docs-before-code.sh.** `search-architecture-docs` must be called before any Write or Edit to application code files. This is a PreToolUse gate — the write is blocked until docs are searched.

### Quality Gates are Non-Negotiable

- **`cargo fmt --check` and `cargo clippy -- -D warnings` must pass** before any session completes. The enforce-quality.sh hook runs these checks on all changed Rust files and blocks completion if violations exist.
- **SAST checks run automatically.** The enforce-sast.sh hook checks Semgrep, cargo-audit, and cargo-deny (when installed). Critical/high severity findings block the session.
- **Completed pipelines must be archived.** The enforce-pipeline-completion.sh hook blocks session completion if a pipeline document in `active/` is marked complete but has not been moved to `completed/`.

### Hook Integrity

- **Hook files must not be modified to weaken enforcement.** Changes to `.claude/hooks/` must go through a pipeline with review, not be made ad-hoc to bypass a blocking check.
- **Hooks must handle missing tools gracefully.** If a required tool (cargo, semgrep) is not installed, the hook exits 0 (allows through) with a warning — it does not crash or produce false blocks.
- **The `stop_hook_active` guard prevents infinite loops.** When a Stop hook blocks and work continues to fix the issue, the hook checks `stop_hook_active` and allows through to prevent recursive blocking.

## 16. Documentation Lookup

- **Architecture and framework documentation lookup is mandatory.** Every phase that designs, implements, tests, reviews, or audits code MUST call `search-architecture-docs` before starting work. This is enforced by both a PreToolUse gate (enforce-docs-before-code.sh) and a Stop hook (enforce-completion.sh).
- **`/design` and `/implement` MUST also call `search-docs`** to verify framework APIs before designing or implementing. Do not rely on training data — read the actual docs.
- **Note:** Golden examples may not exist for early projects. `search-patterns` still provides context from the Forge knowledge base. Absence of golden examples does not excuse skipping the call.
