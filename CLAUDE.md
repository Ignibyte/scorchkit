# ScorchKit

Rust security testing toolkit and orchestrator. **95 modules across three families:** 77 DAST (web scanning) + 13 SAST (code analysis) + 5 Infra (host/network, gated `--features infra`). Claude AI integration, 5 output formats, proxy support, authenticated scanning, scan profiles, scan diffing, unified `assess`.

## Quick Reference

```bash
cargo build                                       # Build (default: DAST + SAST)
cargo build --features infra                      # Build with infrastructure scanning
cargo build --features mcp                        # Build with MCP server (implies storage)
cargo test                                        # Run tests
cargo test --features infra                       # Run with infra tests
cargo run -- run <url>                            # DAST scan
cargo run -- run <url> --profile quick            # Fast DAST scan (4 modules)
cargo run -- run <url> --analyze                  # Scan + AI analysis
cargo run -- run <url> --proxy http://127.0.0.1:8080  # Through Burp
cargo run -- code <path>                          # SAST scan on source code
cargo run -- code <path> --profile quick          # Secrets + deps only
cargo run --features infra -- infra <target>      # Infrastructure scan
cargo run --features infra -- assess --url ... --code ... --infra ...  # All three concurrently
cargo run -- analyze <report.json> -f remediate   # AI remediation guide
cargo run -- diff baseline.json current.json      # Compare two scans
cargo run -- doctor                               # Check tool installation
cargo run -- modules --check-tools                # List all modules
cargo run -- completions bash                     # Shell completions
```

## Claude Code Commands

ScorchKit includes Claude Code slash commands for conversational security testing. Use these inside Claude Code for a guided experience.

### Scanning & Analysis

| Command | Purpose |
|---------|---------|
| `/scan` | Run DAST security scans — profile selection, auth, proxy, module filtering |
| `/code` | Run SAST code analysis — secrets, dependencies, code patterns |
| `/analyze` | AI-powered analysis — summary, prioritize, remediate, filter |
| `/diff` | Compare two scans — track security posture changes |
| `/report` | Generate reports — JSON, HTML, SARIF, PDF |

### Setup & Exploration

| Command | Purpose |
|---------|---------|
| `/tutorial` | Guided walkthrough for new users |
| `/doctor` | Check tool installation, get setup help |
| `/modules` | Explore scan modules and capabilities |

### Project Management (requires PostgreSQL + `--features storage`)

| Command | Purpose |
|---------|---------|
| `/project` | Manage projects — create, targets, status, intelligence |
| `/finding` | Triage findings — lifecycle management, status transitions |
| `/schedule` | Recurring scans — cron-based scheduling |

### Contributing

| Command | Purpose |
|---------|---------|
| `/coder` | Development assistant — architecture docs, module patterns |

## MCP Server Integration

ScorchKit includes an MCP (Model Context Protocol) server that lets Claude use scanning tools directly. See `.claude/mcp.json` for configuration.

```bash
cargo build --features mcp
```

The MCP server exposes tools covering scanning, project management, finding lifecycle, scheduling, and AI analysis.

## Configuration: `[cve]` block (v2.0)

CVE correlation requires `--features infra` and a `[cve]` block in `scorchkit.toml`:

```toml
[cve]
backend = "nvd"        # or "osv" or "mock" or "disabled" (default)

[cve.nvd]
api_key = "your-key"   # optional; SCORCHKIT_NVD_API_KEY env wins over config

[cve.osv]
# OSV is keyless. Defaults: cache_ttl_secs = 86400, max_rps = 10
```

`Engine::infra_scan` reads this and appends `CveMatchModule` automatically. See `docs/modules/cve-nvd.md` and `docs/modules/cve-osv.md`.

## Project Structure

```
src/
  main.rs              Entry point (tokio runtime, tracing)
  lib.rs               Module tree + crate-root re-exports
  facade.rs            Engine facade: scan(), code_scan(), infra_scan(), full_assessment()
  prelude.rs           Convenience re-exports for library consumers
  engine/              Core: Target, Finding, Severity, traits, contexts, shared helpers
                       (cve, tls_probe, service_fingerprint, events, audit_log,
                       compliance, scope, evidence, oob, hook_runner)
  cli/                 Clap CLI (args.rs), command dispatch (runner.rs), shell completions, doctor
  config/              TOML: ScanConfig, AuthConfig, ToolsConfig, AiConfig, ReportConfig,
                       CveConfig (NvdConfig, OsvConfig), HookConfig, WordlistConfig, etc.
  runner/              Orchestrator (DAST), CodeOrchestrator (SAST), InfraOrchestrator (infra),
                       subprocess management, progress, hooks, plugin, rule_engine
  recon/               headers, tech, discovery, subdomain, crawler, dns, js_analysis,
                       cname_takeover, vhost, cloud
  scanner/             ssl, misconfig, csrf, injection, cmdi, xss, ssrf, xxe, idor, jwt,
                       redirect, sensitive, api_schema, ratelimit, cors, csp, auth, upload,
                       websocket, graphql, subtakeover, acl, api, path_traversal, ssti,
                       nosql, ldap, crlf, host_header, smuggling, prototype_pollution,
                       mass_assignment, clickjacking, dom_xss, waf
  tools/               nmap, nuclei, nikto, sqlmap, feroxbuster, sslyze, zap, ffuf, metasploit,
                       wafw00f, testssl, wpscan, amass, subfinder, dalfox, hydra, httpx,
                       theharvester, arjun, cewl, droopescan, katana, gau, paramspider,
                       trufflehog, prowler, trivy, dnsx, gobuster, dnsrecon, enum4linux,
                       interactsh
  sast/                dep_audit (built-in: lockfile auditor across cargo/npm/pip/go)
  sast_tools/          semgrep, osv_scanner, gitleaks, bandit, gosec, phpstan, eslint_security,
                       checkov, hadolint, grype, snyk_code, snyk_test
  infra/               (gated: --features infra)
                       tcp_probe, nmap, cve_match, tls_probe, dns_probe;
                       cve_lookup factory; cve_nvd + cve_osv backends; cve_mock fixture;
                       cve_cache (sha256-keyed FS cache); cpe_purl (CPE -> ecosystem map)
  agent/               Autonomous scan agent (recon -> plan -> scan -> analyze loop)
  ai/                  Claude CLI integration (analyst, planner, prompts, response parser)
  report/              terminal, json, html, sarif, pdf, diff
  mcp/                 MCP server (rmcp, stdio transport, tools, resources)
  storage/             PostgreSQL persistence (sqlx, projects, findings, schedules, metrics,
                       intelligence)
tests/
  cli.rs               CLI integration tests
  cve_nvd.rs           NVD backend integration tests (httpmock + #[ignore]'d live smoke)
  cve_osv.rs           OSV backend integration tests (httpmock + #[ignore]'d live smoke)
  hooks.rs             Hook system tests
  ...
docs/
  architecture/        System design docs (overview, engine, sast, modules)
  modules/             Per-module docs incl. cve-nvd.md, cve-osv.md, tls-infra.md, dns-infra.md
  tools/               Per-tool wrapper docs
  tools-checklist.md   Installation guide for all external tools
```

## Key Conventions

- **Module naming**: `engine/` not `core/` (avoids `std::core` shadow)
- **Error handling**: `engine::error::Result<T>` with `ScorchError` via `thiserror`
- **No unwrap/expect**: denied by clippy; use `?`, `let-else`, `ok_or`, `is_ok_and`
- **Async**: tokio, concurrent module execution via semaphore in each orchestrator
- **Module patterns**:
  - DAST: implement `ScanModule`, register in `recon::register_modules()` / `scanner::register_modules()` / `tools::register_modules()`
  - SAST: implement `CodeModule`, register in `sast::register_modules()` / `sast_tools::register_modules()`
  - Infra: implement `InfraModule`, register in `infra::register_modules()`
- **Finding builder**: `Finding::new(...).with_evidence(...).with_remediation(...).with_owasp(...).with_cwe(...).with_compliance(...)`
- **Proxy**: reqwest `.proxy()` support, configured via `--proxy` flag or `config.toml`. NOTE: vendor API calls (NVD, OSV) deliberately bypass the scan client / proxy.
- **Cookie jar**: `cookie_store(true)` on HTTP client for session persistence
- **Profiles**: quick (4 modules), standard (all built-in), thorough (everything)
- **Scope**: `--scope` and `--exclude` flags, config file support, CIDR-aware
- **Feature flags**:
  - `storage` — PostgreSQL persistence
  - `mcp` — MCP server (implies `storage`)
  - `infra` — infrastructure scanning module family

## CVE backends — extending

To add a third CVE source (CSAF, GitHub Advisory Database, vendor-specific feed):

1. Implement `engine::cve::CveLookup` for the new backend (own its `reqwest::Client`, rate limiter, cache).
2. Add a `CveBackendKind::YourBackend` variant in `config::cve`.
3. Add a `YourConfig` sub-block on `CveConfig` if needed.
4. Add a dispatch arm in `infra::cve_lookup::build_cve_lookup`.
5. Re-export from `prelude` if it's part of the public API.

`engine::cve::cvss_v3_base_score(vector)` is reusable for any backend that surfaces CVSS vector strings rather than numeric scores.

## Documentation

- [Architecture Overview](docs/architecture/overview.md)
- [Engine Internals](docs/architecture/engine.md)
- [SAST Architecture](docs/architecture/sast.md)
- [Module Development Guide](docs/architecture/modules.md)
- [CVE NVD backend](docs/modules/cve-nvd.md)
- [CVE OSV backend](docs/modules/cve-osv.md)
- [TLS infra](docs/modules/tls-infra.md)
- [DNS infra](docs/modules/dns-infra.md)
- [Built-in Module Docs](docs/modules/)
- [Tool Wrapper Docs](docs/tools/)
- [Tools Installation Guide](docs/tools-checklist.md)
