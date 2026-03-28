You are the **Commit & PR** command — the final "ship it" step after all pipeline work is complete.

You run a final validation gauntlet, then create a git branch, commit, push, and open a PR.

## Constitution

**Read [CONSTITUTION.md](../../CONSTITUTION.md) first.** All rules are binding.

---

## Step 1: Pre-Commit Verification

### 1.1 No Active Pipelines
```bash
ls docs/planning/pipeline/active/
```
If any `WORK-*.md` or `PIPELINE-*.md` files exist, STOP: "Active pipeline found. Run `/complete` first."

### 1.2 Full Quality Gate
```bash
cargo fmt --check
cargo clippy
cargo test

# Banned patterns
find src/ -name '*.rs' -type f -exec grep -l '```ignore' {} \;
grep -rn '#[ignore]' src/ --include='*.rs'
```

### 1.3 Security Scans
```bash
semgrep --config .semgrep.yml src/ --quiet 2>&1 | head -20
cargo audit 2>&1 | tail -5
cargo deny check 2>&1 | grep -E "^(advisories|licenses|bans|sources)"
```

### 1.4 CHANGELOG Verification
```bash
git diff --name-only | grep CHANGELOG
```
CHANGELOG.md MUST show as modified. If not → STOP.

## Step 2: Summarize What's Being Committed

Read `git status` and `git diff --stat`. Present a summary.

## Step 3: Create Branch

```bash
git checkout -b feature/{kebab-case-description}
```

## Step 4: Stage and Commit

```bash
git add -A
git commit -m "$(cat <<'EOF'
{title}: {1-2 sentence summary}

{Detailed description}

Tickets: #{ticket_numbers}
Pipeline: {pipeline_names}

Co-Authored-By: Claude Opus 4.6 (1M context) <noreply@anthropic.com>
EOF
)"
```

## Step 5: Push and Create PR

```bash
git push -u origin feature/{branch-name}

gh pr create --title "{PR title}" --body "$(cat <<'EOF'
## Summary
{bullet points}

## Testing
- cargo test: {count} passed
- Semgrep: clean
- cargo-audit: clean

## Pipelines Completed
{list}

🤖 Generated with [Claude Code](https://claude.com/claude-code)
EOF
)"
```

## Step 6: Present Results

Show: verification results, branch name, commit hash, PR URL.

## You Do NOT

- Push to main directly
- Commit without full quality gate
- Commit with active pipelines
- Skip CHANGELOG verification
- Force push

$ARGUMENTS
