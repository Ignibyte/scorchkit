# Changelog

All notable changes to ScorchKit will be documented in this file.

## [0.9.0] - 2026-04-13

### Added
- **Claude Code command suite** — 11 slash commands for conversational security testing: `/scan`, `/analyze`, `/diff`, `/doctor`, `/modules`, `/report`, `/tutorial`, `/project`, `/finding`, `/schedule`, `/coder`
- **MCP server** — 24 tools for native Claude Code integration via Model Context Protocol (stdio transport)
- **AI-powered analysis** — Claude integration for scan planning, finding prioritization, remediation guidance, and false positive filtering
- **Project management** — Persistent vulnerability tracking with PostgreSQL: projects, targets, scan history, posture metrics, module intelligence
- **Scan scheduling** — Cron-based recurring scans with `schedule create` and `schedule run-due`
- **Finding confidence scores** — Per-finding confidence (0.0-1.0) with `--min-confidence` CLI filter
- **Scan resume/checkpoint** — `--resume` flag recovers interrupted scans from checkpoint files
- **Inter-module data sharing** — Recon modules share discovered URLs, forms, and parameters with scanners
- **Multi-target scanning** — `--targets-file` flag scans multiple targets from a file
- **Custom wordlists** — `[wordlists]` config section for directory, subdomain, vhost, and parameter fuzzing lists
- **Scan templates** — Pre-built module sets: web-app, api, graphql, wordpress, spa, network, full
- **Scan diffing** — `diff` command compares two scan reports for posture tracking
- **77 scan modules:**
  - 10 recon: headers, tech, discovery, subdomain, crawler, dns, js_analysis, cname_takeover, vhost, cloud
  - 35 scanners: ssl, misconfig, csrf, injection, cmdi, xss, ssrf, xxe, idor, jwt, redirect, sensitive, api_schema, ratelimit, cors, csp, auth, upload, websocket, graphql, subtakeover, acl, api, path_traversal, ssti, nosql, ldap, crlf, host_header, smuggling, prototype_pollution, mass_assignment, clickjacking, dom_xss, waf
  - 32 external tool wrappers: nmap, nuclei, nikto, sqlmap, feroxbuster, sslyze, zap, ffuf, metasploit, wafw00f, testssl, wpscan, amass, subfinder, dalfox, hydra, httpx, theharvester, arjun, cewl, droopescan, katana, gau, paramspider, trufflehog, prowler, trivy, dnsx, gobuster, dnsrecon, enum4linux, interactsh
- **4 output formats** — Terminal (colored), JSON, HTML, SARIF
- **Autonomous agent** — `agent` command runs recon-plan-scan-analyze loop
- **Doctor command** — Tool installation verification with `--deep` version checks
- **Proxy support** — Route scans through Burp Suite, ZAP, or any HTTP proxy
- **Shell completions** — bash, zsh, fish, PowerShell via `completions` command
