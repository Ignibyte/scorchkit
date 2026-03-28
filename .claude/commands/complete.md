You are executing **Phase 6: Complete** for a Work Pipeline in ScorchKit.

This is the final phase. Documentation, changelog, knowledge recording, and the Final Pipeline Checklist.

## Constitution

**Read [CONSTITUTION.md](../../CONSTITUTION.md) first.** All rules are binding.

---

## Step 1: Locate the Pipeline

Read `docs/planning/pipeline/active/` and find the active `WORK-*.md` pipeline document. If none exist, STOP.

## Step 2: Entry Verification — INDEPENDENTLY VERIFY PHASE 5

**Do NOT trust Phase 5's self-reported results.** Re-run:

```bash
cargo test
cargo clippy
find src/ -name '*.rs' -type f -exec grep -l '```ignore' {} \;
```

**Show actual output.** If ANY fails → STOP: "Entry verification failed."

Also verify:
- Phase 5 Status = PASS
- ALL phases 1-5 show PASS
- Forge Ticket ID matches a valid ticket (call `ticket-get`)

## Step 3: Bootstrap Context

1. **Call `bootstrap`**
2. **Call `recall`** with `agent="docs", phase=6`

## Step 4: Documentation

### 4.1 Architecture Decisions (if any were made)

1. Create `docs/architecture/` if needed
2. Write or update `docs/architecture/{topic}.md`
3. Include: the decision, rationale, alternatives, date

### 4.2 API Documentation

- If new public APIs were added → run `cargo doc --no-deps`
- Keep updates proportional to the change

## Step 5: Update Changelog

Update `CHANGELOG.md`:
- New feature = MINOR bump
- Bug fix = PATCH bump
- Breaking change = MAJOR bump

## Step 6: Self-Reflection (MANDATORY)

1. **Did any phase use workarounds?**
2. **Was the implementation the cleanest version?**
3. **Would a senior Rust developer approve?**

## Step 7: After-Action Review — Record Knowledge

1. **Call `save-generation-trace`** with pipeline data, `pipeline_type="work"`, `work_title`, `component_types`
2. **Call `learn`** for each lesson
3. **Call `report-failure`** for each failure

## Step 8: Final Pipeline Checklist (MANDATORY)

### Pipeline Document Integrity
- [ ] Forge Ticket ID (UUID) matches a real ticket
- [ ] ALL phases (1-5) show Status = PASS
- [ ] Phase 1 has a complete Work Spec
- [ ] Phase 2 has a File Manifest with specific paths
- [ ] Phase 2 has a Regression Test Plan
- [ ] Phase 3 has Files Created/Modified lists
- [ ] Phase 3 has Quality Gates with actual results
- [ ] Phase 4 has Entry Verification results
- [ ] Phase 4 has Code Review results
- [ ] Phase 4 has Test Results with actual counts
- [ ] Phase 5 has Cargo Test count

### Code Quality (re-verify right now)
- [ ] `cargo fmt --check` = 0 diffs
- [ ] `cargo clippy` = 0 warnings
- [ ] `cargo test` = 0 failures
- [ ] `find src/ -name '*.rs' -exec grep -l '```ignore' {} \;` = 0 files
- [ ] `grep -rn '#[ignore]' src/ --include='*.rs'` = 0 matches

### Knowledge Recording
- [ ] `bootstrap` called
- [ ] `recall` called
- [ ] `learn` called
- [ ] `save-generation-trace` called
- [ ] CHANGELOG.md updated

### Documentation
- [ ] Architecture decisions documented locally (if any)
- [ ] `cargo doc --no-deps` builds

**If ALL items pass, proceed to archive. If ANY fail, fix first.**

## Step 9: Archive Pipeline

1. Update Phase 6: Status = PASS, checklist results, self-reflection
2. Move pipeline doc from `active/` to `completed/`
3. Close Forge ticket via `ticket-close`

## Step 10: Build Verification

```bash
cargo build --all-targets
cargo doc --no-deps 2>&1 | grep -c "warning"
```

## Step 11: Present Final Results

Show: checklist, docs, changelog, self-reflection, knowledge recorded, archive path, ticket closed, "Pipeline complete."

## You Do NOT

- Archive before the checklist passes
- Skip self-reflection
- Leave pipeline docs in `active/`
- Skip knowledge recording

$ARGUMENTS
