# 03 — Unified `assess` (DAST + SAST + Infra in one command)

**Goal:** scan a service from three angles in a single pass — web app, source code, and infrastructure host — and read the merged report.

**Time:** ~30 minutes (bulk is the scan itself).

**You'll need:** ScorchKit built with `--features infra`. Three things you control about one service:

- A **URL** you can hit (web-app entrypoint)
- The **source code** for that service on disk
- An **infra target** — IP or hostname of the box it runs on

---

## 1. Why use `assess` at all?

You can run `sk run`, `sk code`, and `sk infra` separately and concatenate the reports. `assess` is the convenience: one command, three orchestrators in parallel via `tokio::join!`, results merged into a single `ScanResult`. Same `[scope]`, `[auth]`, `[ai]`, `[report]` config across all three — no duplicate setup.

Best for: assessment days, security-review checkpoints, "I want one report I can hand to the team."

## 2. Define the target

For this tutorial, imagine a hypothetical service:

| | Value |
|---|-------|
| URL | `https://api.your-service.com` |
| Source code | `~/src/your-service-api` |
| Infra host | `api.your-service.com` |

(For a hands-on dry run, use `https://httpbin.org`, the ScorchKit repo itself for `--code`, and `scanme.nmap.org` for `--infra`. The findings won't be related but the workflow proves out.)

## 3. The single command

```bash
sk assess \
    --url   https://api.your-service.com \
    --code  ~/src/your-service-api \
    --infra api.your-service.com
```

The three orchestrators kick off concurrently. Failures in any one domain log a warning and skip to the next — partial results still come back. Output is the standard terminal report with findings from all three families merged and sorted by severity.

## 4. Add CVE correlation

If you've configured `[cve]` (see [tutorial 02](02-cve-correlation.md)), `assess` picks it up automatically — `Engine::infra_scan` consults `build_cve_lookup` whether it's invoked directly or via `assess`.

```bash
sk assess --url https://api.your-service.com --code ~/src/your-service-api --infra api.your-service.com -c scorchkit.toml
```

## 5. Save and analyse

```bash
sk assess --url ... --code ... --infra ... -o json
sk analyze scorchkit-report.json -f summary
sk analyze scorchkit-report.json -f prioritize
```

`analyze` runs Claude over the merged report. `summary` produces an executive overview; `prioritize` ranks findings by exploitability and (when enabled) suggests attack chains across the three families.

## 6. Per-domain skipping

Need to skip one domain? Just omit its flag:

```bash
sk assess --url https://api.your-service.com --infra api.your-service.com
# No --code -> SAST orchestrator skipped, DAST + Infra still run
```

At least one of the three is required. All three optional would error with `assess requires at least one of --url, --code, or --infra`.

## 7. Reading the merged report

The terminal output groups findings by severity, not by family. To filter by source family later:

```bash
# Just SAST findings
sk analyze scorchkit-report.json -f filter --include-modules semgrep,gitleaks,bandit,gosec

# Just infra findings
sk analyze scorchkit-report.json -f filter --include-modules tcp_probe,nmap,cve_match,tls_infra,dns_infra

# Just DAST scanner findings (exclude recon noise)
sk analyze scorchkit-report.json -f filter --exclude-modules headers,tech,discovery,subdomain,crawler
```

Or open the JSON: every finding has a `module_id` field that tells you which scanner produced it.

## 8. Where to go next

- **[04 — Claude Code workflow](04-claude-code-workflow.md)** — same `assess` flow but conversational, with AI in the loop end-to-end
- **[08 — CI/CD integration](08-ci-cd-integration.md)** — run `assess` on every PR, gate the build on critical findings

---

## Things that go wrong

| Symptom | Cause | Fix |
|---------|-------|-----|
| One domain returns no findings even though you expect some | The domain's orchestrator failed silently — check stderr for `assess: domain failed: ...` warnings | Re-run with `RUST_LOG=debug` for the failing domain to see the underlying error |
| The merged report is huge | Three families produce a lot of Info findings | Use `--severity medium` or higher; or filter via `analyze -f filter` after the fact |
| `code` scan takes forever | A SAST tool is hanging on a deep repo (often Semgrep on a monorepo) | `--code-modules dep_audit,gitleaks` to skip Semgrep; or set `--code-profile quick` |
