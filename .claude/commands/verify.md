You are executing **Phase 5: Verify** for a Work Pipeline in ScorchKit.

You run the full test suite to catch regressions. This is the final quality gate before completion.

## Constitution

**Read [CONSTITUTION.md](../../CONSTITUTION.md) first.** All rules are binding.

---

## Step 1: Locate the Pipeline

Read `docs/planning/pipeline/active/` and find the active `WORK-*.md` pipeline document. If none exist, STOP.

## Step 2: Entry Verification — INDEPENDENTLY VERIFY PHASE 4

**Do NOT trust Phase 4's self-reported results.** Re-run everything:

```bash
# 1. Tests must still pass
cargo test

# 2. Clippy must still be clean
cargo clippy

# 3. Formatting must still be clean
cargo fmt --check

# 4. Doctests must compile
cargo test --doc
```

**Show actual output.** If ANY fails → STOP: "Entry verification failed."

Also verify: Phase 4 Status = PASS in the pipeline document.

## Step 2.5: Bootstrap Context

1. **Call `bootstrap`**
2. **Call `recall`** with `agent="tester", phase=5`

## Step 3: Full Test Suite

### Cargo Tests
```bash
cargo test -- --nocapture
```

Record:
- Total tests passed
- Total tests failed
- Any regressions vs Phase 4 test count

### Integration Tests
```bash
cargo test --test '*'
```

Record:
- Integration test count and results

### Regression Check

Compare test counts:
- Phase 4 cargo test count vs Phase 5 cargo test count — must be >= (no lost tests)
- Any test that passed in Phase 4 but fails now = REGRESSION → FAIL

## Step 4: Update Pipeline Document

Update Phase 5 section with: Status, Cargo test count and result, Regressions. Update header: Next Step = "Run `/complete` for Phase 6"

## Step 5: Record Knowledge

- Call `learn` with verification lessons
- Call `report-failure` for any regressions

## Step 6: Present Results

Show: entry verification, cargo test results, regression analysis. "Run `/complete` to finish." or "FAILED — fix and re-run."

## You Do NOT

- Skip entry verification
- Trust Phase 4 results without re-running
- Claim PASS without showing test output
- Ignore regressions

$ARGUMENTS
