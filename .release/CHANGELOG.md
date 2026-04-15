# Changelog

All notable changes to ScorchKit will be documented in this file.

## [2.0.0] - 2026-04-14

The v2.0 arc adds **infrastructure scanning** as a third module family parallel to DAST and SAST, **CVE correlation** with two production backends (NVD + OSV), and the unified **`assess`** command that runs all three families concurrently and merges the results.

### Added

#### Infrastructure scanning (new module family)

- **`InfraModule` trait + `InfraOrchestrator`** — third module family parallel to `ScanModule` (DAST) and `CodeModule` (SAST). New `InfraTarget` sum type supports IPs, CIDR ranges, hostnames, and `host:port` endpoints. Same `Finding` / report pipeline as the other two families. `InfraCategory` enum: `PortScan`, `Fingerprint`, `CveMatch`, `TlsInfra`, `Dns`. **All five categories ship populated in v2.0.**
- **`scorchkit infra <target>`** — new CLI subcommand (gated `--features infra`). Profile, modules, and skip flags work the same as the DAST `run` subcommand.
- **`Engine::infra_scan(target)`** — facade method for library consumers.
- **`TcpProbeModule`** — privilege-free TCP-connect reachability probe against a configurable port list. Default ports cover SSH, web, common databases, and high-port web. (`PortScan`)
- **`NmapModule` (infra)** — `nmap -sV` invocation that produces `ServiceFingerprint`s and publishes them to `shared_data` so the CVE matcher and other downstream modules can consume them. The DAST `tools::NmapModule` was refactored to use the same shared parser. (`Fingerprint`)
- **`ServiceFingerprint` shared-data API** — `port`, `protocol`, `service_name`, `product`, `version`, `cpe` published under a constant key with `publish_fingerprints` / `read_fingerprints` helpers. Bridges fingerprinting and CVE correlation.
- **`CveLookup` async trait + `CveMatchModule`** — module reads `Vec<ServiceFingerprint>` from shared data, queries the configured backend per-fingerprint, and emits one finding per matched CVE with the CVSS score in the title and evidence. (`CveMatch`)
- **`NvdCveLookup` — production NIST NVD 2.0 backend**: separate `reqwest::Client` from the scan client (so pen-test proxy / insecure-TLS settings never leak into vendor calls), `governor::RateLimiter` sized to NVD's published quotas (5/30s anonymous, 50/30s with API key), content-addressed file-system TTL cache (`infra::cve_cache::FsCache`, sha256-keyed, with negative caching). Bad API keys (401/403) auto-disable in-process so a misconfigured credential doesn't burn the per-fingerprint loop. `SCORCHKIT_NVD_API_KEY` env var beats config.
- **`OsvCveLookup` — production OSV.dev backend**: sibling impl behind the same trait. Embedded ≥30-entry CPE → (ecosystem, package_name) translator covering `npm` / `PyPI` / `Maven` / `Go` / `crates.io` / `RubyGems` / `NuGet` / `Packagist`. Faithful in-process CVSS v3.1 base-score computer (`engine::cve::cvss_v3_base_score`) handles OSV's vector-string severities. Per-backend cache directory (`scorchkit/cve-osv/` vs `scorchkit/cve/`) prevents cross-contamination. Conservative 10 RPS limit under OSV's ~25 QPS fair-use cap. Keyless.
- **`[cve]` config block** — `backend = "disabled" | "mock" | "nvd" | "osv"` discriminant + per-backend sub-block (`[cve.nvd]` and `[cve.osv]`). `infra::cve_lookup::build_cve_lookup(&AppConfig)` factory returns the configured backend. `Engine::infra_scan` consults the factory and appends `CveMatchModule` automatically.
- **`TlsInfraModule`** — non-HTTP TLS handshake + certificate analysis on SMTPS (465), LDAPS (636), IMAPS (993), POP3S (995) via implicit TLS, plus SMTP (25 / 587), IMAP (143), POP3 (110) via protocol-specific STARTTLS upgrade. Uses the same four cert checks as the DAST `ssl` module (expired, self-signed, weak signature, host mismatch); closed ports surface as Info findings rather than errors. Shared core in new `engine::tls_probe` module. (`TlsInfra`)
- **`DnsInfraModule`** — native async DNS hygiene probes via `hickory-resolver`: wildcard A/AAAA detection (16-hex-char random label per scan, 64 bits of UUID-derived entropy), DNSSEC presence check (`DNSKEY`), CAA record presence, NS enumeration. (`Dns`)

#### Unified assessment

- **`scorchkit assess --url ... --code ... --infra ...`** — runs the DAST, SAST, and infra orchestrators concurrently via `tokio::join!` and merges results into a single `ScanResult`. At least one of the three flags is required; per-domain failures are logged at `warn` and skipped so partial results still return.
- **`Engine::full_assessment(url, code_path, infra_target)`** — facade method for library consumers.

#### SAST expansion

- **9 additional SAST tool wrappers** — Bandit (Python), Checkov (IaC), ESLint security (JS/TS), Gosec (Go), Grype (containers + deps), Hadolint (Dockerfile), PHPStan (PHP), Snyk Code (commercial SAST, free tier), Snyk Test (commercial SCA, free tier). Brings SAST tool count from 3 → 12.
- **`sast::dep_audit`** — first built-in SAST module. Parses `Cargo.lock`, `package-lock.json`, `requirements.txt`, and `go.sum` with no external tools required. Detects duplicate package versions (supply-chain risk), unpinned dependencies (reproducibility risk), and known-risky / compromised packages.
- **`/code` slash command** — Claude Code conversational SAST experience.

#### Engine improvements

- **`engine::tls_probe`** — shared TLS-probe core (`CertInfo`, `TlsMode`, `StarttlsProtocol`, `probe_tls`, `parse_certificate`, `check_certificate`). DAST `scanner::ssl` and infra `infra::tls_probe` both consume it; one source of truth for cert analysis across the codebase.
- **`engine::cve::cvss_v3_base_score(vector)`** — faithful in-process implementation of the CVSS v3.1 base-score formula. Reusable by any future vector-surfacing CVE backend.
- **`engine::events`** — in-process `tokio::sync::broadcast`-backed event bus for scan-lifecycle events. Multi-subscriber fanout, fire-and-forget publish. Custom-event support via `ScanEvent::Custom` and filtered subscriptions via `subscribe_filtered`.
- **`engine::audit_log`** — JSONL audit-log handler subscribes to the event bus and appends every published event to a configurable file. Opt-in via `[audit_log]` in `config.toml`.
- **`engine::compliance`** — OWASP → framework mapping (PCI-DSS, NIST CSF, ISO 27001) attached to findings via `with_compliance()`.
- **`engine::scope`** — `ScopeRule` enum (Exact, Wildcard, CIDR) with bitwise CIDR matching for `--scope` / `--exclude` flags.

#### Tooling & process

- **YAML rule templates** — `rules/examples/` directory with example custom rules; `runner::rule_engine` evaluates them at scan time.
- **Webhook notifications** — `[webhooks]` config block fires fire-and-forget POSTs on `scan_started` / `scan_completed` / `finding_discovered`.
- **Scan hooks (script-based)** — `[hooks]` config block runs operator scripts at `pre_scan`, `post_module`, `post_scan` lifecycle points. Supports JSON I/O and configurable timeouts.
- **Custom wordlists** — `[wordlists]` config block lets operators override the built-in default wordlists for directory / subdomain / vhost / parameter modules.
- **`scorchkit init`** — fingerprint a target then write a tailored `scorchkit.toml` with the recommended profile, scope, rate limit, and module suggestions.
- **Examples** — `examples/custom_scanner` (DAST) and `examples/custom_code_scanner` (SAST) for library consumers.
- **`Engine` facade + `prelude`** — `cargo add scorchkit` ships a usable library API. Crate-root re-exports for `Finding`, `Severity`, `Target`, `ScanResult`, `Result`, `ScorchError`. Async `Engine::scan(url)` / `Engine::code_scan(path)` / `Engine::infra_scan(target)` / `Engine::full_assessment(...)`.

### Changed

- **DAST `scanner::ssl` refactored** to delegate cert extraction and analysis to `engine::tls_probe`. Behavior preserved — DAST findings unchanged in shape; only the call-site changes. Eliminates the duplication that DAST and infra would otherwise carry.
- **DAST `tools::nmap` refactored** to share `parse_nmap_xml_fingerprints` with the new infra `nmap` module.
- **`InfraOrchestrator::register_default_modules()`** registers `tcp_probe`, `nmap`, `tls_infra`, `dns_infra` by default; `cve_match` is added by the orchestrator construction path when `[cve] backend != "disabled"`.

### Numbers

- **Modules**: 80 → **95** (45 DAST built-in + 32 DAST tool wrappers + 13 SAST + 5 infra)
- **Tests on `--features infra`**: 0 → **675** (default 559, mcp 701)
- **Public API surface**: facade methods + prelude re-exports for the new infra/SAST families
- **No new heavy crate deps** in the DAST/SAST paths; new infra deps (`hickory-resolver`, `governor`, `sha2`) are gated behind `--features infra`

---

## [1.0.0] - 2026-04-13

### Added

#### SAST (Static Application Security Testing)
- **Code scanning subcommand** — `scorchkit code <path>` scans source code with `--language`, `--modules`, `--skip`, `--profile` flags
- **CodeModule trait** — parallel to ScanModule, path-based context for static analysis
- **CodeOrchestrator** — concurrent SAST module execution with semaphore throttling and profiles
- **Semgrep wrapper** — multi-language static analysis with CWE/OWASP metadata extraction
- **OSV-Scanner wrapper** — dependency vulnerability scanning across all ecosystems (Google OSV database)
- **Gitleaks wrapper** — secret detection with automatic evidence redaction (first 8 chars only)
- **Language detection** — auto-detects project language from 16 manifest file patterns
- **SAST profiles** — quick (secrets + SCA), standard (all tools), thorough (all tools)
- **`run_tool_lenient()`** — subprocess helper for tools that exit non-zero when findings exist
- **`Target::from_path()`** — enables all existing reporting/storage/AI for code findings

#### Claude Code Integration
- **11 slash commands** for conversational security testing: `/scan`, `/analyze`, `/diff`, `/doctor`, `/modules`, `/report`, `/tutorial`, `/project`, `/finding`, `/schedule`, `/coder`
- **MCP server config template** — `.claude/mcp.json` for Claude Code MCP integration

#### DAST (Dynamic Application Security Testing)
- **77 DAST modules** — 10 recon, 35 vulnerability scanners, 32 external tool wrappers
- **AI-powered analysis** — Claude integration for scan planning, finding prioritization, remediation guidance, and false positive filtering
- **Project management** — persistent vulnerability tracking with PostgreSQL: projects, targets, scan history, posture metrics, module intelligence
- **Scan scheduling** — cron-based recurring scans with `schedule create` and `schedule run-due`
- **Finding confidence scores** — per-finding confidence (0.0-1.0) with `--min-confidence` CLI filter
- **Scan resume/checkpoint** — `--resume` flag recovers interrupted scans from checkpoint files
- **Inter-module data sharing** — recon modules share discovered URLs, forms, and parameters with scanners
- **Multi-target scanning** — `--targets-file` flag scans multiple targets from a file
- **Custom wordlists** — `[wordlists]` config section for directory, subdomain, vhost, and parameter fuzzing
- **Scan templates** — pre-built module sets: web-app, api, graphql, wordpress, spa, network, full
- **Scan diffing** — `diff` command compares two scan reports for posture tracking
- **Autonomous agent** — `agent` command runs recon-plan-scan-analyze loop
- **Doctor command** — tool installation verification with `--deep` version checks (DAST + SAST tools)
- **4 output formats** — Terminal (colored), JSON, HTML, SARIF
- **Proxy support** — route scans through Burp Suite, ZAP, or any HTTP proxy
- **Shell completions** — bash, zsh, fish, PowerShell via `completions` command
- **MCP server** — 24 tools for native Claude integration via Model Context Protocol (stdio transport)

#### Modules
- **80 total modules:**
  - 10 recon: headers, tech, discovery, subdomain, crawler, dns, js_analysis, cname_takeover, vhost, cloud
  - 35 scanners: ssl, misconfig, csrf, injection, cmdi, xss, ssrf, xxe, idor, jwt, redirect, sensitive, api_schema, ratelimit, cors, csp, auth, upload, websocket, graphql, subtakeover, acl, api, path_traversal, ssti, nosql, ldap, crlf, host_header, smuggling, prototype_pollution, mass_assignment, clickjacking, dom_xss, waf
  - 32 DAST tool wrappers: nmap, nuclei, nikto, sqlmap, feroxbuster, sslyze, zap, ffuf, metasploit, wafw00f, testssl, wpscan, amass, subfinder, dalfox, hydra, httpx, theharvester, arjun, cewl, droopescan, katana, gau, paramspider, trufflehog, prowler, trivy, dnsx, gobuster, dnsrecon, enum4linux, interactsh
  - 3 SAST tool wrappers: semgrep, osv-scanner, gitleaks
