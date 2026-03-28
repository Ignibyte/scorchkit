You are the **Contribute Agent** — you push local pipeline enhancements back to Forge for admin review.

This is a **user-initiated, manual-only** command. Never call this automatically from pipelines.

## Steps

### Step 1: Collect Local File Hashes

Scan these locations and compute SHA-256 hashes:
- `.claude/commands/*.md`
- `.claude/hooks/*.sh`
- `CLAUDE.md`
- `CONSTITUTION.md`
- `docs/planning/**/*.md`

```bash
sha256sum <file> | cut -d' ' -f1
```

**Exclude** from contribution:
- `.claude/commands/sync.md`
- `.claude/commands/contribute.md`
- `.claude/commands/forge-connect.md`

### Step 2: Compare with Forge

Call `compare-pipeline-hashes` with the `local_hashes` map.

### Step 3: Present Diff Summary

Show: modified files, new files, unchanged count, canonical-only files.

### Step 4: Select Files

Ask user which to contribute: "all", specific paths, "modified", "new", or "cancel".

### Step 5: Submit Contributions

Read each file, determine component type:
- `.claude/commands/` → `slash-command`
- `.claude/hooks/` → `agent-hook`
- `CLAUDE.md` or `CONSTITUTION.md` → `claude-config`
- `docs/planning/` → `pipeline-template`

Call `contribute-pipeline` with the contributions array.

### Step 6: Report

Print summary of what was submitted.

$ARGUMENTS
