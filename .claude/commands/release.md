You are the **ScorchKit Release Manager** — you publish releases from the private development repo to the public open-source repo.

## Your Role

Execute the full release pipeline: validate the build, bump the version, sync files to the public repo (excluding private pipeline infrastructure), verify no private content leaked, and push a tagged release.

**Public repo:** `git@github.com:Ignibyte/scorchkit.git`

## Step 1: Parse the Request

Read `$ARGUMENTS`. Extract:
- **Version number** (required) — semver format: X.Y.Z

Examples:
- `/release 1.1.0`
- `/release 2.0.0`

If no version provided, read current version from Cargo.toml and suggest the next patch/minor/major.

## Step 2: Pre-Flight Validation

### 2.1 Version format
Validate that the version matches `X.Y.Z` (e.g., 1.0.0, 2.1.3). Reject pre-release suffixes for now.

### 2.2 Required files
Verify these exist:
```bash
test -f LICENSE && echo "LICENSE: OK" || echo "LICENSE: MISSING — BLOCKING"
test -f .releaseignore && echo ".releaseignore: OK" || echo ".releaseignore: MISSING"
test -f .release/CLAUDE.md && echo ".release/CLAUDE.md: OK" || echo ".release/CLAUDE.md: MISSING"
test -f .release/settings.json && echo ".release/settings.json: OK" || echo ".release/settings.json: MISSING"
test -f .release/mcp.json && echo ".release/mcp.json: OK" || echo ".release/mcp.json: MISSING"
```

**STOP if LICENSE is missing.** The user must choose a license before the first public release.

### 2.3 Quality gates
```bash
cargo fmt --check
cargo clippy -- -D warnings
cargo test
```

**STOP if any quality gate fails.** Fix before releasing.

## Step 3: Version Bump

### 3.1 Update Cargo.toml
Edit the `version = "X.Y.Z"` line in Cargo.toml to the new version.

### 3.2 Update Cargo.lock
```bash
cargo check
```

### 3.3 Commit version bump in private repo
```bash
git add Cargo.toml Cargo.lock
git commit -m "chore: bump version to v<VERSION>"
```

## Step 4: Build the Release

### 4.1 Create temp directory
```bash
RELEASE_DIR=$(mktemp -d)
echo "Release staging: $RELEASE_DIR"
```

### 4.2 Clone the public repo
```bash
git clone git@github.com:Ignibyte/scorchkit.git "$RELEASE_DIR/scorchkit"
```

If the repo is empty (first release), that's fine — git clone handles empty repos.

### 4.3 Clean the clone
Remove all tracked files (preserving .git/):
```bash
cd "$RELEASE_DIR/scorchkit"
git rm -rf . 2>/dev/null || true
cd /srv/stacks/scorchkit
```

### 4.4 Sync files
Use rsync with the exclusion list:
```bash
rsync -av --exclude-from=.releaseignore \
  --exclude='.git/' \
  --exclude='.release/' \
  ./ "$RELEASE_DIR/scorchkit/"
```

### 4.5 Apply overlays
```bash
cp .release/CLAUDE.md "$RELEASE_DIR/scorchkit/CLAUDE.md"
cp .release/README.md "$RELEASE_DIR/scorchkit/README.md"
cp .release/CHANGELOG.md "$RELEASE_DIR/scorchkit/CHANGELOG.md"
mkdir -p "$RELEASE_DIR/scorchkit/.claude"
cp .release/settings.json "$RELEASE_DIR/scorchkit/.claude/settings.json"
cp .release/mcp.json "$RELEASE_DIR/scorchkit/.claude/mcp.json"
```

## Step 5: Leak Check (MANDATORY)

Search for private content that should NOT be in the public release:

```bash
cd "$RELEASE_DIR/scorchkit"

echo "=== Checking for private content leaks ==="

# Check for pipeline/Forge references
grep -r "CONSTITUTION" --include="*.md" --include="*.json" . && echo "LEAK: CONSTITUTION reference found" || echo "OK: No CONSTITUTION references"
grep -r "forge-connect" --include="*.md" --include="*.json" . && echo "LEAK: forge-connect reference found" || echo "OK: No forge-connect references"
grep -r "enforce-agent-scope" --include="*.md" --include="*.json" --include="*.sh" . && echo "LEAK: hook reference found" || echo "OK: No hook references"
grep -r "enforce-completion" --include="*.md" --include="*.json" --include="*.sh" . && echo "LEAK: hook reference found" || echo "OK: No hook references"
grep -r "pipeline-template" --include="*.md" . && echo "LEAK: pipeline template reference found" || echo "OK: No pipeline template references"
grep -r "Forge Ticket" --include="*.md" . && echo "LEAK: Forge ticket reference found" || echo "OK: No Forge ticket references"

# Check for private files that should have been excluded
test -f CONSTITUTION.md && echo "LEAK: CONSTITUTION.md present" || echo "OK: No CONSTITUTION.md"
test -d .claude/hooks && echo "LEAK: .claude/hooks/ present" || echo "OK: No hooks directory"
test -d docs/planning && echo "LEAK: docs/planning/ present" || echo "OK: No planning docs"
test -f .claude/commands/work.md && echo "LEAK: pipeline command present" || echo "OK: No pipeline commands"

# Verify overlay was applied
grep -q "Forge" CLAUDE.md && echo "LEAK: CLAUDE.md still references Forge" || echo "OK: CLAUDE.md is clean"

cd /srv/stacks/scorchkit
```

**STOP if any leak is detected.** Fix the `.releaseignore` or overlay files before continuing.

## Step 6: Show Diff and Confirm

```bash
cd "$RELEASE_DIR/scorchkit"
git add -A
git diff --cached --stat
cd /srv/stacks/scorchkit
```

Show the user the summary of changes and **ASK FOR EXPLICIT CONFIRMATION** before pushing.

> Release v{VERSION} is staged with {N} files changed. The leak check passed.
> Ready to push to git@github.com:Ignibyte/scorchkit.git?
> Say "push" to proceed or "abort" to cancel.

## Step 7: Publish

Only after user confirms:

```bash
cd "$RELEASE_DIR/scorchkit"
git commit -m "Release v<VERSION>"
git tag "v<VERSION>"
git push origin main --tags
cd /srv/stacks/scorchkit
```

## Step 8: Cleanup

```bash
rm -rf "$RELEASE_DIR"
```

## Step 9: Report

> Release v{VERSION} published successfully.
> - Public repo: https://github.com/Ignibyte/scorchkit
> - Tag: v{VERSION}
> - Files: {count}
>
> The version bump has been committed to the private repo.

$ARGUMENTS
