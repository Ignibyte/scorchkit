# 01 — Your first scan

**Goal:** install ScorchKit, confirm your toolchain, scan one URL, read the report.

**Time:** ~30 minutes (mostly waiting for cargo to compile the first time).

**You'll need:** Linux or macOS with Rust 1.70+. A target URL you have permission to scan — for this tutorial we'll use `https://httpbin.org` (a public test endpoint).

---

## 1. Build

```bash
git clone https://github.com/Ignibyte/scorchkit.git
cd scorchkit
cargo build --release
```

The first build pulls a lot of dependencies and takes 5–10 minutes. Subsequent builds are seconds. The compiled binary lands at `./target/release/scorchkit`.

For shorter commands during the tutorial, alias it:

```bash
alias sk=./target/release/scorchkit
```

## 2. Health-check the environment

```bash
sk doctor
```

You'll see a table of every external pentest tool ScorchKit can wrap. Most show as **MISSING** on a fresh install — that's fine. ScorchKit's built-in modules (15 web scanners + 10 recon modules) work without any external tools.

For this tutorial you don't need to install anything else. Note any `MISSING` rows that interest you for later — `doctor` prints the install command for each.

## 3. Run a quick scan

```bash
sk run https://httpbin.org --profile quick
```

The `quick` profile runs four modules: HTTP security headers, technology fingerprinting, TLS analysis, and the misconfiguration scanner. It finishes in under 30 seconds against most targets.

You'll see a colored terminal report with findings grouped by severity. Each finding has:
- A **title** (e.g. "Missing Strict-Transport-Security header")
- A **severity** (Critical → High → Medium → Low → Info)
- The **affected resource** (URL, header, parameter)
- **Evidence** (what ScorchKit observed)
- A **remediation hint** (what to do about it)
- An **OWASP** / **CWE** mapping where applicable

## 4. Save the report

Re-run with JSON output:

```bash
sk run https://httpbin.org --profile quick -o json
```

This writes `scorchkit-report.json` to the current directory. The JSON includes everything you saw in the terminal, plus per-finding metadata (timestamps, confidence scores, request/response evidence). It's the input format for `sk diff` and `sk analyze`.

## 5. Try the standard profile

```bash
sk run https://httpbin.org
```

The default `standard` profile runs all 15 built-in scanners — injection probes, CSRF detection, SSL analysis, sensitive-data exposure, etc. Takes 1–3 minutes against a typical target.

You'll see noticeably more findings, especially **Info** ones. Info findings aren't bugs — they're observations (e.g. "discovered admin path exists at `/admin`"). They become useful as input to follow-up scans.

## 6. Filter the noise

```bash
# Hide low-confidence findings (likely false positives)
sk run https://httpbin.org --min-confidence 0.7

# Only specific modules
sk run https://httpbin.org --modules ssl,headers,misconfig

# Skip slow or noisy modules
sk run https://httpbin.org --skip nuclei,sqlmap
```

There is no built-in `--severity` filter on `run` — if you want a severity-gated view, emit JSON (`-o json`) and filter with `jq` (see [tutorial 08](08-ci-cd-integration.md) §2 for the pattern).

## 7. Where to go next

- **[02 — CVE correlation](02-cve-correlation.md)** — match service banners against NVD or OSV
- **[04 — Claude Code workflow](04-claude-code-workflow.md)** — same scans but conversational
- **[08 — CI/CD integration](08-ci-cd-integration.md)** — run ScorchKit on every PR

---

## Things that go wrong

| Symptom | Cause | Fix |
|---------|-------|-----|
| `cargo build` fails on `aws-lc-rs` | System-level cmake/clang missing | `sudo apt install cmake clang` (Debian/Ubuntu) or `brew install cmake llvm` (macOS) |
| `connection refused` against your own target | Local dev server uses self-signed TLS | Add `--insecure` to skip cert verification (only use against your own dev targets) |
| Scan stuck for >10 minutes | Network-bound module is hanging | Add `--profile quick` to limit to fast modules; or `--skip nuclei,sqlmap` to drop the slow ones |
