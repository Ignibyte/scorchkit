# Changelog

All notable changes to ScorchKit will be documented in this file.

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
