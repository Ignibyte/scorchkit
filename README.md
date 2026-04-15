# ScorchKit

A Rust-based web application security testing toolkit and orchestrator. DAST + SAST + Infra in one binary, with Claude AI integration for intelligent analysis of findings.

- **DAST** — 41 web-app modules covering the OWASP Top 10 (built-in scanners + 21 external tool wrappers).
- **SAST** — code scanning via the `code` subcommand (built-in + tool wrappers).
- **Infra** (v2.0, `--features infra`) — host/network probes for port scan, service fingerprinting, **CVE correlation against NVD or OSV**, **TLS hygiene** (SMTPS/LDAPS/IMAPS/POP3S + STARTTLS on SMTP/IMAP/POP3), and **DNS hygiene** (wildcard, DNSSEC, CAA, NS).
- **Unified `assess`** — DAST + SAST + Infra in one command via `scorchkit assess --url ... --code ... --infra ...`.

## Install

```bash
git clone https://github.com/chadpeppers/scorchkit.git
cd scorchkit
cargo build --release
# Binary at ./target/release/scorchkit
```

## Quick Start

```bash
# Scan a target
scorchkit run https://example.com

# Quick scan (4 modules: headers, tech, SSL, misconfig)
scorchkit run https://example.com --profile quick

# Thorough scan (all modules including external tools)
scorchkit run https://example.com --profile thorough

# Scan with AI analysis
scorchkit run https://example.com --analyze

# Scan through Burp Suite proxy
scorchkit run https://example.com --proxy http://127.0.0.1:8080

# Recon only
scorchkit recon https://example.com

# Specific modules
scorchkit run https://example.com --modules headers,ssl,misconfig

# Check what tools are installed
scorchkit doctor
```

## Modules (41)

### Built-in Recon (6)

| Module | ID | Description | Docs |
|--------|----|-------------|------|
| HTTP Security Headers | `headers` | HSTS, CSP, X-Frame-Options, etc. (15 checks) | [docs/modules/headers.md](docs/modules/headers.md) |
| Technology Fingerprinting | `tech` | Server, framework, CMS detection (90+ signatures) | [docs/modules/tech.md](docs/modules/tech.md) |
| Directory & File Discovery | `discovery` | Sensitive paths, admin panels, backups (28 probes) | [docs/modules/discovery.md](docs/modules/discovery.md) |
| Subdomain Enumeration | `subdomain` | DNS brute-force (57 prefixes) | [docs/modules/subdomain.md](docs/modules/subdomain.md) |
| Web Crawler | `crawler` | Link following, form/parameter/JS route discovery | [docs/modules/crawler.md](docs/modules/crawler.md) |
| WAF Detection | `waf` | Cloudflare, Sucuri, ModSecurity, etc. (27 signatures) | [docs/modules/waf.md](docs/modules/waf.md) |

### Built-in Scanners (15)

| Module | ID | OWASP | Description | Docs |
|--------|----|-------|-------------|------|
| TLS/SSL Analysis | `ssl` | A02 | Certificate validation, expiry, weak algorithms | [docs/modules/ssl.md](docs/modules/ssl.md) |
| Security Misconfiguration | `misconfig` | A05 | CORS, cookies, error pages, HTTP methods | [docs/modules/misconfig.md](docs/modules/misconfig.md) |
| CSRF Detection | `csrf` | A05 | Missing CSRF tokens on POST forms | [docs/modules/csrf.md](docs/modules/csrf.md) |
| SQL Injection | `injection` | A03 | Error-based + blind SQLi (10 payloads, 30 error patterns) | [docs/modules/injection.md](docs/modules/injection.md) |
| Command Injection | `cmdi` | A03 | OS command injection (7 payloads) | [docs/modules/cmdi.md](docs/modules/cmdi.md) |
| Reflected XSS | `xss` | A03 | Canary injection + 6 XSS payloads | [docs/modules/xss.md](docs/modules/xss.md) |
| SSRF Detection | `ssrf` | A10 | Internal URL injection (10 payloads inc. cloud metadata) | [docs/modules/ssrf.md](docs/modules/ssrf.md) |
| XXE Detection | `xxe` | A05 | XML external entity injection | [docs/modules/xxe.md](docs/modules/xxe.md) |
| IDOR Detection | `idor` | A01 | ID manipulation in params and path segments | [docs/modules/idor.md](docs/modules/idor.md) |
| JWT Analysis | `jwt` | A02 | alg:none, weak signing, sensitive claims, expiry | [docs/modules/jwt.md](docs/modules/jwt.md) |
| Open Redirect | `redirect` | A01 | Redirect parameter injection (17 param names) | [docs/modules/redirect.md](docs/modules/redirect.md) |
| Sensitive Data Exposure | `sensitive` | A02 | API keys, secrets, PII, source maps (15 patterns) | [docs/modules/sensitive.md](docs/modules/sensitive.md) |
| API Schema Discovery | `api-schema` | A05 | OpenAPI/Swagger + GraphQL introspection | [docs/modules/api-schema.md](docs/modules/api-schema.md) |
| Rate Limit Testing | `ratelimit` | A07 | Brute-force protection on login endpoints | [docs/modules/ratelimit.md](docs/modules/ratelimit.md) |

### External Tool Wrappers (21)

Install any tool and it automatically activates. Missing tools are skipped gracefully. Run `scorchkit doctor` to see what's installed.

| Module | Tool | Category | Docs |
|--------|------|----------|------|
| `nmap` | nmap | Port scanning | [docs/tools/nmap.md](docs/tools/nmap.md) |
| `nuclei` | Nuclei | Template vuln scanning | [docs/tools/nuclei.md](docs/tools/nuclei.md) |
| `nikto` | Nikto | Web server scanning | [docs/tools/nikto.md](docs/tools/nikto.md) |
| `sqlmap` | SQLMap | SQL injection | [docs/tools/sqlmap.md](docs/tools/sqlmap.md) |
| `feroxbuster` | Feroxbuster | Directory brute-force | [docs/tools/feroxbuster.md](docs/tools/feroxbuster.md) |
| `sslyze` | SSLyze | TLS/SSL analysis | [docs/tools/sslyze.md](docs/tools/sslyze.md) |
| `zap` | OWASP ZAP | Web app scanner | [docs/tools/zap.md](docs/tools/zap.md) |
| `ffuf` | ffuf | Web fuzzer | [docs/tools/ffuf.md](docs/tools/ffuf.md) |
| `metasploit` | Metasploit | Exploit validation | [docs/tools/metasploit.md](docs/tools/metasploit.md) |
| `wafw00f` | wafw00f | WAF detection | [docs/tools/wafw00f.md](docs/tools/wafw00f.md) |
| `testssl` | testssl.sh | TLS testing | [docs/tools/testssl.md](docs/tools/testssl.md) |
| `wpscan` | WPScan | WordPress scanning | [docs/tools/wpscan.md](docs/tools/wpscan.md) |
| `amass` | Amass | Subdomain enumeration | [docs/tools/amass.md](docs/tools/amass.md) |
| `subfinder` | Subfinder | Subdomain discovery | [docs/tools/subfinder.md](docs/tools/subfinder.md) |
| `dalfox` | Dalfox | XSS scanning | [docs/tools/dalfox.md](docs/tools/dalfox.md) |
| `hydra` | Hydra | Credential testing | [docs/tools/hydra.md](docs/tools/hydra.md) |
| `httpx` | httpx | HTTP probing | [docs/tools/httpx.md](docs/tools/httpx.md) |
| `theharvester` | theHarvester | OSINT | [docs/tools/theharvester.md](docs/tools/theharvester.md) |
| `arjun` | Arjun | Parameter discovery | [docs/tools/arjun.md](docs/tools/arjun.md) |
| `cewl` | CeWL | Wordlist generation | [docs/tools/cewl.md](docs/tools/cewl.md) |
| `droopescan` | Droopescan | CMS scanning | [docs/tools/droopescan.md](docs/tools/droopescan.md) |

### Infrastructure scanning (v2.0, `--features infra`)

Probes hosts, IPs, and CIDR ranges. Same `Finding` / report pipeline as DAST. Run with `scorchkit infra <target>` or include in a unified scan via `scorchkit assess --infra <target>`.

| Module | Category | Description | Docs |
|--------|----------|-------------|------|
| `tcp_probe` | PortScan | Privilege-free TCP-connect reachability against a configurable port list | — |
| `nmap` (infra) | PortScan + Fingerprint | `nmap -sV` with shared service-fingerprint publication for downstream CVE correlation | — |
| `cve_match` | CveMatch | Correlate detected service fingerprints against a `CveLookup` backend (NVD or OSV) | [docs/modules/cve-nvd.md](docs/modules/cve-nvd.md) · [docs/modules/cve-osv.md](docs/modules/cve-osv.md) |
| `tls_infra` | TlsInfra | TLS handshake + cert analysis on SMTPS/LDAPS/IMAPS/POP3S + STARTTLS on SMTP (25/587), IMAP (143), POP3 (110) | [docs/modules/tls-infra.md](docs/modules/tls-infra.md) |
| `dns_infra` | Dns | Wildcard A/AAAA detection, DNSSEC presence (DNSKEY), CAA record presence, NS enumeration | [docs/modules/dns-infra.md](docs/modules/dns-infra.md) |

CVE backends are config-driven via `[cve]` in `config.toml`:

```toml
[cve]
backend = "nvd"   # or "osv" or "mock" or "disabled"

[cve.nvd]
api_key = "..."   # optional; or set SCORCHKIT_NVD_API_KEY
```

## AI Analysis

Requires [Claude Code](https://docs.anthropic.com/en/docs/claude-code) CLI.

```bash
scorchkit run https://example.com --analyze              # Scan + AI summary
scorchkit analyze report.json                            # Analyze saved report
scorchkit analyze report.json --focus summary            # Executive summary
scorchkit analyze report.json --focus prioritize         # Risk ranking + attack chains
scorchkit analyze report.json --focus remediate          # Tech-specific fix instructions
scorchkit analyze report.json --focus filter             # False positive identification
```

## Output Formats

```bash
scorchkit run https://example.com --output terminal      # Colored terminal (default)
scorchkit run https://example.com --output json           # JSON report
scorchkit run https://example.com --output html           # Self-contained HTML report
scorchkit run https://example.com --output sarif          # SARIF for CI/CD (GitHub, Azure DevOps)
```

## Scan Comparison

```bash
scorchkit diff baseline.json current.json                # Show new, resolved, unchanged findings
```

## Authenticated Scanning

```toml
# config.toml
[auth]
bearer_token = "eyJ..."
# OR
cookies = "session=abc123; csrftoken=xyz"
# OR
username = "admin"
password = "password"
# OR
custom_header = "X-API-Key"
custom_header_value = "your-key"
```

## Proxy Support (Burp Suite / ZAP)

```bash
scorchkit run https://example.com --proxy http://127.0.0.1:8080
```

Or in `config.toml`:
```toml
[scan]
proxy = "http://127.0.0.1:8080"
```

## Scope Control

```bash
scorchkit run https://example.com --scope "*.example.com" --exclude "/logout"
```

## Configuration

```bash
scorchkit init                    # Generate default config.toml
scorchkit doctor                  # Check external tool installation
scorchkit modules --check-tools   # List modules with tool status
```

## Shell Completions

```bash
scorchkit completions bash > ~/.local/share/bash-completion/completions/scorchkit
scorchkit completions zsh > ~/.zfunc/_scorchkit
scorchkit completions fish > ~/.config/fish/completions/scorchkit.fish
```

## Documentation

- [Architecture Overview](docs/architecture/overview.md)
- [Module Development Guide](docs/architecture/modules.md)
- [External Tools Checklist](docs/tools-checklist.md)
- [Individual Module Docs](docs/modules/)
- [Individual Tool Docs](docs/tools/)

## License

MIT - see [LICENSE](LICENSE)
