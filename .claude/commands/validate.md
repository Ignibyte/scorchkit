You are executing **Phase 4: Validate** for a Work Pipeline in ScorchKit.

You are the quality gate — you review code AND run tests. Nothing advances without your honest assessment.

## Constitution

**Read [CONSTITUTION.md](../../CONSTITUTION.md) first.** All rules are binding.

---

## Step 1: Locate the Pipeline

Read `docs/planning/pipeline/active/` and find the active `WORK-*.md` pipeline document. If none exist, STOP.

## Step 2: Entry Verification — INDEPENDENTLY VERIFY PHASE 3

**Do NOT trust the pipeline document's claim that Phase 3 passed.** Run these checks yourself:

```bash
# 1. Formatting
cargo fmt --check

# 2. Linting
cargo clippy

# 3. Tests
cargo test

# 4. Banned doctests
find src/ -name '*.rs' -type f -exec grep -l '```ignore' {} \;

# 5. Banned #[ignore] on tests
grep -rn '#\[ignore\]' src/ --include='*.rs'

# 6. #[allow] workarounds without justification
# (check changed .rs files for #[allow(...)] not preceded by // JUSTIFICATION:)
```

**Show the actual output of each command.** If checks 1-3 fail → STOP: "Phase 3 entry verification FAILED."

## Step 3: Bootstrap Context

1. **Call `bootstrap`**
2. **Call `recall`** with `agent="review", phase=4`
3. **Call `search-architecture-docs`**

## Step 4: Code Review

Read every file listed in Phase 3 "Files Created" and "Files Modified". Check:

### Documentation
- [ ] All `pub` items have `///` doc comments
- [ ] Module files have `//!` module-level doc comments

### Error Handling
- [ ] No `unwrap()` or `expect()` in library code
- [ ] Error types use `thiserror` with descriptive messages
- [ ] `?` operator used for propagation

### Type Design
- [ ] All types derive `Debug`
- [ ] No unnecessary allocations or clones

### Safety
- [ ] No `unsafe` without `// SAFETY:` comment
- [ ] Async types are `Send + Sync`

### Code Quality
- [ ] Iterators preferred over explicit loops
- [ ] Exhaustive pattern matching
- [ ] No dead code or unused imports

### Workaround Detection
- [ ] No `#[allow(...)]` without `// JUSTIFICATION:` comment
- [ ] No `#[ignore]` on any test functions
- [ ] No `#![allow(unused)]` or `#![allow(dead_code)]` crate-level suppressions
- [ ] No ` ```ignore ` in any doctests

## Step 5: Run Tests

```bash
cargo test -- --nocapture
cargo test --doc
```

## Step 5.5: Coverage Check (if cargo-tarpaulin is installed)

```bash
if command -v cargo-tarpaulin &>/dev/null; then
    cargo tarpaulin --out stdout --skip-clean 2>&1 | tail -20
fi
```

## Step 5.6: Security Scan

```bash
semgrep --config .semgrep.yml src/ --quiet 2>&1 | head -30
cargo audit 2>&1 | tail -10
```

## Step 6: Assess Test Quality

### 6.1 Regression Test Plan Compliance
Read the Phase 2 Regression Test Plan. For each test listed, verify it exists.

### 6.2 Test Quality Review
- Are tests testing meaningful behavior or just compilation?
- Are error paths tested?
- Are edge cases covered?

## Step 7: Update Pipeline Document

Update Phase 4 section with: Status, Entry Verification results, Code Review findings, Test Results, Notes. Update header.

## Step 8: Record Knowledge

- Call `learn` with review/testing lessons
- Call `report-failure` for any issues found

## Step 9: Present Results

Show: entry verification results, code review summary, test results, assessment. "Run `/verify` when ready." or "FAILED — run `/implement` to fix."

## You Do NOT

- Skip entry verification
- Trust Phase 3's self-reported results
- Rubber-stamp code you haven't read
- Claim PASS without running cargo commands

$ARGUMENTS
