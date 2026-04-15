# 08 — CI/CD integration

**Goal:** wire ScorchKit into your CI so every PR runs a relevant scan and the build fails on regressions. Examples for GitHub Actions and GitLab CI.

**Time:** ~30 minutes per pipeline.

**You'll need:** A repo with CI access. ScorchKit installed in the CI image (or built in a job step). For GitHub: write access to push the workflow.

---

## 1. The model

ScorchKit fits CI/CD in three places:

1. **SAST on every PR** — fast, deterministic, no external infrastructure needed. Block the PR if anything Critical lands.
2. **DAST on every successful deploy to staging** — slower, needs the deploy URL, often runs after smoke tests pass.
3. **Infra scan on a schedule** — daily or weekly against production. Reports flow into a posture-tracking dashboard.

Pick the one that's most painful for your org and start there.

## 2. SAST on every PR (GitHub Actions)

`.github/workflows/scorchkit-sast.yml`:

```yaml
name: ScorchKit SAST

on:
  pull_request:
  push:
    branches: [main]

jobs:
  sast:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4

      - name: Install ScorchKit
        run: |
          # Pre-built binary release once available; for now build from source
          git clone https://github.com/Ignibyte/scorchkit.git
          cd scorchkit
          cargo build --release
          sudo mv target/release/scorchkit /usr/local/bin/

      - name: Install SAST tools
        run: |
          # Quick profile only needs gitleaks + the built-in dep_audit
          # No extra install needed — built-in
          # Plus optionally:
          go install github.com/google/osv-scanner/cmd/osv-scanner@latest
          echo "$HOME/go/bin" >> $GITHUB_PATH

      - name: Run SAST scan
        run: |
          scorchkit code . --profile quick -o sarif

      - name: Upload SARIF to GitHub Security
        if: always()
        uses: github/codeql-action/upload-sarif@v3
        with:
          sarif_file: scorchkit-report.sarif

      - name: Fail on Critical findings
        run: |
          # Re-run as JSON for jq filtering
          scorchkit code . --profile quick -o json
          CRITICAL=$(jq '[.findings[] | select(.severity == "Critical")] | length' scorchkit-report.json)
          echo "Critical findings: $CRITICAL"
          if [ "$CRITICAL" -gt 0 ]; then
            jq '[.findings[] | select(.severity == "Critical")] | .[]' scorchkit-report.json
            exit 1
          fi
```

The `upload-sarif` step lights up GitHub's Security tab — findings show inline on the PR's "Files changed" view, which is where reviewers will actually see them.

## 3. DAST on staging deploy (GitHub Actions)

Trigger after a successful staging deploy. Adjust the trigger event for whatever your deploy workflow emits.

```yaml
name: ScorchKit DAST (staging)

on:
  workflow_run:
    workflows: ["Deploy to Staging"]
    types: [completed]

jobs:
  dast:
    if: github.event.workflow_run.conclusion == 'success'
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4

      - name: Install ScorchKit
        run: |
          # ... same as above

      - name: Quick scan
        run: |
          scorchkit run https://staging.your-app.com --profile quick -o sarif

      - name: Upload SARIF
        uses: github/codeql-action/upload-sarif@v3
        with:
          sarif_file: scorchkit-report.sarif

      - name: Diff against last week
        run: |
          # Pull last week's report from your artifact store / S3 / wherever
          # aws s3 cp s3://your-bucket/scorchkit-baselines/staging-latest.json baseline.json
          # scorchkit diff baseline.json scorchkit-report.json -o json > diff.json
          # Optional: post diff to Slack / email
```

## 4. Infra scan on a schedule (GitHub Actions)

```yaml
name: ScorchKit Infra (production)

on:
  schedule:
    - cron: '0 9 * * 1'  # 09:00 UTC every Monday
  workflow_dispatch:

jobs:
  infra:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - name: Install ScorchKit (with infra)
        run: |
          git clone https://github.com/Ignibyte/scorchkit.git
          cd scorchkit
          cargo build --release --features infra
          sudo mv target/release/scorchkit /usr/local/bin/

      - name: Configure NVD
        env:
          SCORCHKIT_NVD_API_KEY: ${{ secrets.SCORCHKIT_NVD_API_KEY }}
        run: |
          cat > scorchkit.toml <<EOF
          [cve]
          backend = "nvd"

          [cve.nvd]
          # api_key picked up from env
          EOF

      - name: Scan
        env:
          SCORCHKIT_NVD_API_KEY: ${{ secrets.SCORCHKIT_NVD_API_KEY }}
        run: |
          scorchkit infra your-prod-host.example.com -c scorchkit.toml -o json

      - name: Archive report
        uses: actions/upload-artifact@v4
        with:
          name: infra-report-${{ github.run_id }}
          path: scorchkit-report.json
```

## 5. GitLab CI equivalent

`.gitlab-ci.yml` snippet:

```yaml
scorchkit_sast:
  stage: test
  image: rust:1.70
  script:
    - git clone https://github.com/Ignibyte/scorchkit.git
    - cd scorchkit && cargo build --release && cd ..
    - ./scorchkit/target/release/scorchkit code . --profile quick -o sarif
    - ./scorchkit/target/release/scorchkit code . --profile quick -o json
    - |
      CRITICAL=$(jq '[.findings[] | select(.severity == "Critical")] | length' scorchkit-report.json)
      if [ "$CRITICAL" -gt 0 ]; then exit 1; fi
  artifacts:
    when: always
    paths:
      - scorchkit-report.sarif
      - scorchkit-report.json
    reports:
      sast: scorchkit-report.sarif
```

GitLab's `artifacts.reports.sast` slot integrates the SARIF directly into the merge request UI.

## 6. Performance tips

- **Cache the cargo build.** `actions/cache` keyed on `Cargo.lock` cuts a 5-minute build to seconds.
- **Pin a release tag.** Once ScorchKit ships a binary release, point at `https://github.com/Ignibyte/scorchkit/releases/download/v2.0.0/scorchkit-x86_64-linux.tar.gz` instead of building from source.
- **Skip slow modules in CI.** Most SAST tools are fast; Semgrep on a monorepo isn't. Use `--modules dep_audit,gitleaks,bandit` or `--profile quick` to keep the PR loop tight.
- **Run different profiles per branch.** `quick` on every PR, `standard` on merges to main, `thorough` on the schedule.

## 7. Severity gating policy

Where to draw the line is org-specific, but a sensible default:

| Severity | Action on PR | Action on schedule |
|----------|--------------|--------------------|
| Critical | Block merge | Page on-call |
| High | Require review approval | File issue |
| Medium | Comment on PR | Track on dashboard |
| Low / Info | Surface in SARIF tab | Ignore unless trending up |

The `jq '[.findings[] | select(.severity == "...")] | length'` snippet from §2 is the building block for any of these.

## 8. Where to go next

- **[02 — CVE correlation](02-cve-correlation.md)** — get the NVD or OSV API key set up before the scheduled infra scan
- **[03 — Unified assess](03-unified-assess.md)** — one CI job that runs all three families against the same target

---

## Things that go wrong

| Symptom | Cause | Fix |
|---------|-------|-----|
| SARIF upload fails | GitHub limits SARIF to 25k runs | Filter the report before upload: `jq '...' scorchkit-report.sarif > filtered.sarif` |
| CI takes 15 minutes building scorchkit | First build is from source | Cache `~/.cargo` and `target/`; or wait for the binary release |
| `cve_match` returns nothing in CI but works locally | Cache directory is per-runner — first scan repopulates from scratch each time | Mount a persistent cache volume; or accept the first-scan cost |
| Quick scan still finds Info noise | Quick profile is for speed, not signal-to-noise | There is no `--severity` flag; filter the JSON with `jq '[.findings[] \| select(.severity != "Info" and .severity != "Low")]'` before emitting the SARIF or consuming the report |
