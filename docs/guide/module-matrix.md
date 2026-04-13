# Module Matrix — Tool Selection Reference

Use this table to select the right modules for your target type. Filter by OWASP category, target type, or scan purpose.

## Quick Selection by Target Type

| Target Type | Recommended Modules | Profile |
|-------------|-------------------|---------|
| **Web Application** | headers, tech, ssl, misconfig, csrf, injection, xss, ssrf, xxe, path_traversal, ssti, redirect, sensitive, auth, upload, clickjacking, cors, csp, crawler, discovery | standard |
| **REST API** | headers, ssl, misconfig, injection, nosql, api, api_schema, cors, jwt, ratelimit, auth, idor | standard + `--modules` |
| **GraphQL API** | headers, ssl, graphql, injection, cors, jwt, auth, ratelimit | `--modules graphql,headers,ssl,injection,cors,jwt,auth,ratelimit` |
| **WordPress** | headers, tech, ssl, misconfig, wpscan, nuclei, discovery | standard + wpscan |
| **Single Page App (SPA)** | headers, ssl, cors, csp, dom_xss, js_analysis, xss, api, jwt, clickjacking | `--modules` selection |
| **Authenticated App** | All standard + auth config in config.toml | standard with `[auth]` config |
| **Cloud/Infrastructure** | ssl, headers, dns, subdomain, cloud, smuggling, cname_takeover | standard |
| **Internal/Dev (DDEV, Docker)** | headers, tech, misconfig, injection, xss, auth, api_schema, sensitive | standard + `-k` |

## Full Module Reference

### Recon Modules (10)

| Module ID | Purpose | OWASP | Target Type | Confidence | Ext Tool |
|-----------|---------|-------|-------------|------------|----------|
| `headers` | Security header analysis (HSTS, X-Frame-Options, X-Content-Type-Options, Permissions-Policy) | A05 Security Misconfiguration | All Web | 0.9 | No |
| `tech` | Technology fingerprinting (server, framework, CMS, cookies) | A05 Security Misconfiguration | All Web | 0.7 | No |
| `discovery` | Directory/file discovery (admin panels, backups, config files, source control) | A01 Broken Access Control | All Web | 0.6 | No |
| `crawler` | Web spider — discovers URLs, forms, parameters, JS files. Publishes to SharedData. | A01 Broken Access Control | All Web | 0.5 | No |
| `subdomain` | DNS brute-force subdomain enumeration | A05 Security Misconfiguration | Domains | 0.8 | No |
| `dns` | DNS record analysis (SPF, DMARC, DKIM, zone transfer) | A05 Security Misconfiguration | Domains | 0.8 | No |
| `waf` | WAF detection and fingerprinting | A05 Security Misconfiguration | All Web | 0.7 | No |
| `cname_takeover` | Dangling CNAME detection + cert transparency enumeration | A05 Security Misconfiguration | Domains | 0.7 | No |
| `vhost` | Virtual host discovery via Host header brute-force | A05 Security Misconfiguration | Web Servers | 0.6 | No |
| `cloud` | Cloud provider detection (AWS/GCP/Azure headers) + S3 bucket enumeration | A01 Broken Access Control | Cloud | 0.7 | No |
| `js_analysis` | JavaScript analysis — secrets, API endpoints, source maps | A01 Broken Access Control | SPAs, Web Apps | 0.6 | No |

### Scanner Modules (35)

#### Injection (9 modules)

| Module ID | Purpose | OWASP | Target Type | Confidence | Ext Tool |
|-----------|---------|-------|-------------|------------|----------|
| `injection` | SQL injection via error-based detection in params and forms | A03 Injection | Web Apps, APIs | 0.8 | No |
| `xss` | Reflected XSS via canary injection in params and forms | A03 Injection | Web Apps | 0.8 | No |
| `cmdi` | OS command injection via shell metacharacter payloads | A03 Injection | Web Apps | 0.8 | No |
| `ssrf` | Server-side request forgery via URL parameter manipulation | A10 SSRF | Web Apps, APIs | 0.7 | No |
| `xxe` | XML external entity injection | A05 Security Misconfiguration | XML APIs | 0.7 | No |
| `nosql` | NoSQL injection (MongoDB operators, error-based) | A03 Injection | MongoDB Apps | 0.7 | No |
| `ldap` | LDAP filter injection via metacharacter payloads | A03 Injection | LDAP Apps | 0.7 | No |
| `ssti` | Server-side template injection across 8 template engines | A03 Injection | Web Apps | 0.8 | No |
| `path_traversal` | Path traversal / LFI with encoding bypass variants | A01 Broken Access Control | Web Apps | 0.8 | No |

#### Authentication & Session (6 modules)

| Module ID | Purpose | OWASP | Target Type | Confidence | Ext Tool |
|-----------|---------|-------|-------------|------------|----------|
| `auth` | Session security — cookie flags, fixation, entropy, credentials in responses | A07 Auth Failures | Web Apps | 0.7 | No |
| `csrf` | CSRF token detection on forms | A01 Broken Access Control | Web Apps | 0.7 | No |
| `jwt` | JWT analysis — algorithm, expiry, claims, none-algorithm attack | A02 Crypto Failures | APIs | 0.8 | No |
| `idor` | Insecure direct object reference via ID manipulation | A01 Broken Access Control | APIs | 0.5 | No |
| `acl` | Access control bypass via path manipulation and method override | A01 Broken Access Control | Web Apps | 0.6 | No |
| `ratelimit` | Brute-force protection testing on login endpoints | A07 Auth Failures | Web Apps | 0.6 | No |

#### Configuration & Headers (6 modules)

| Module ID | Purpose | OWASP | Target Type | Confidence | Ext Tool |
|-----------|---------|-------|-------------|------------|----------|
| `ssl` | TLS certificate analysis — expiry, weak signatures, self-signed, SANs | A02 Crypto Failures | All HTTPS | 0.9 | No |
| `misconfig` | Security misconfiguration — debug modes, default creds, error disclosure | A05 Security Misconfiguration | Web Apps | 0.8 | No |
| `cors` | CORS policy analysis — wildcard origins, credential exposure | A05 Security Misconfiguration | APIs | 0.9 | No |
| `csp` | Content Security Policy analysis — unsafe-inline, missing directives | A05 Security Misconfiguration | Web Apps | 0.9 | No |
| `clickjacking` | Frame protection — X-Frame-Options + CSP frame-ancestors | A05 Security Misconfiguration | Web Apps | 0.9 | No |
| `redirect` | Open redirect detection via redirect parameter injection | A01 Broken Access Control | Web Apps | 0.8 | No |

#### Advanced (8 modules)

| Module ID | Purpose | OWASP | Target Type | Confidence | Ext Tool |
|-----------|---------|-------|-------------|------------|----------|
| `sensitive` | Sensitive data exposure — secrets, tokens, keys in responses | A02 Crypto Failures | All Web | 0.7 | No |
| `api` | REST API security — mass assignment, shadow endpoints, verb tampering | A04 Insecure Design | APIs | 0.7 | No |
| `api_schema` | OpenAPI/Swagger spec discovery and analysis | A05 Security Misconfiguration | APIs | 0.7 | No |
| `graphql` | GraphQL introspection, batch query, depth limit testing | A05 Security Misconfiguration | GraphQL | 0.7 | No |
| `websocket` | WebSocket endpoint discovery and security testing | A05 Security Misconfiguration | Real-time Apps | 0.7 | No |
| `upload` | File upload security — extension bypass, content type confusion | A04 Insecure Design | Web Apps | 0.6 | No |
| `subtakeover` | Subdomain takeover via dangling DNS + service fingerprints | A05 Security Misconfiguration | Domains | 0.8 | No |
| `smuggling` | HTTP request smuggling heuristic detection (proxy indicators, TE obfuscation) | A05 Security Misconfiguration | Multi-tier | 0.5 | No |

#### Client-Side (4 modules)

| Module ID | Purpose | OWASP | Target Type | Confidence | Ext Tool |
|-----------|---------|-------|-------------|------------|----------|
| `dom_xss` | DOM XSS via static source/sink analysis in JavaScript | A07 Auth Failures | SPAs | 0.4 | No |
| `crlf` | CRLF injection / HTTP response splitting | A03 Injection | Web Apps | 0.9 | No |
| `host_header` | Host header injection / cache poisoning | A05 Security Misconfiguration | Web Apps | 0.8 | No |
| `prototype_pollution` | JavaScript prototype pollution via __proto__ injection | A08 Software Integrity | Node.js Apps | 0.5 | No |
| `mass_assignment` | Mass assignment / over-posting via extra JSON fields | A04 Insecure Design | APIs | 0.6 | No |

### External Tool Wrappers (32)

| Module ID | Tool | Purpose | OWASP | Target Type | Confidence |
|-----------|------|---------|-------|-------------|------------|
| `nmap` | Nmap | Port scanning and service detection | A05 | Infrastructure | 0.9 |
| `nuclei` | Nuclei | Template-based vulnerability scanning (CVEs, misconfigs) | Multiple | All Web | 0.8 |
| `nikto` | Nikto | Legacy web server scanner | A05 | Web Servers | 0.6 |
| `sqlmap` | SQLMap | Automated SQL injection confirmation and exploitation | A03 | Web Apps | 0.9 |
| `feroxbuster` | Feroxbuster | Recursive directory brute-force | A01 | Web Apps | 0.6 |
| `sslyze` | SSLyze | Deep TLS/SSL analysis (Heartbleed, ROBOT, cipher suites) | A02 | HTTPS | 0.9 |
| `zap` | OWASP ZAP | Full web application security scanner | Multiple | Web Apps | 0.7 |
| `ffuf` | ffuf | Fast web fuzzer (directories, parameters, vhosts) | A01 | Web Apps | 0.6 |
| `metasploit` | Metasploit | Exploit framework for confirmed vulnerabilities | Multiple | Infrastructure | 0.9 |
| `wafw00f` | wafw00f | WAF product identification | A05 | Web Apps | 0.7 |
| `testssl` | testssl.sh | Comprehensive TLS testing | A02 | HTTPS | 0.9 |
| `wpscan` | WPScan | WordPress vulnerability scanner (plugins, themes, users) | Multiple | WordPress | 0.8 |
| `amass` | Amass | Subdomain enumeration (passive + active) | A05 | Domains | 0.8 |
| `subfinder` | Subfinder | Fast passive subdomain discovery | A05 | Domains | 0.8 |
| `dalfox` | Dalfox | Advanced XSS scanner with WAF bypass | A03 | Web Apps | 0.8 |
| `hydra` | Hydra | Login brute-force tester | A07 | Auth Forms | 0.9 |
| `httpx` | httpx | HTTP probe and technology detection | A05 | Web Apps | 0.8 |
| `theharvester` | theHarvester | OSINT — emails, hosts, subdomains | A05 | Domains | 0.6 |
| `arjun` | Arjun | Hidden HTTP parameter discovery | A04 | Web Apps | 0.7 |
| `cewl` | CeWL | Custom wordlist generation from target content | — | Web Apps | 0.5 |
| `droopescan` | Droopescan | Drupal/Joomla/SilverStripe CMS scanner | Multiple | CMS | 0.7 |
| `katana` | Katana | Fast web crawler | A01 | Web Apps | 0.7 |
| `gau` | gau | Passive URL collection from archives | A01 | Domains | 0.6 |
| `paramspider` | ParamSpider | Parameter mining from web archives | A04 | Web Apps | 0.6 |
| `trufflehog` | TruffleHog | Secret detection in repos and responses | A02 | Source Code | 0.8 |
| `prowler` | Prowler | AWS/Azure/GCP cloud security audit | A05 | Cloud | 0.8 |
| `trivy` | Trivy | Container and dependency vulnerability scanner | A06 | Containers | 0.8 |
| `dnsx` | DNSx | DNS toolkit (resolution, brute-force) | A05 | Domains | 0.8 |
| `gobuster` | Gobuster | Directory/DNS/vhost brute-force | A01 | Web Apps | 0.6 |
| `dnsrecon` | dnsrecon | DNS enumeration and zone transfer testing | A05 | Domains | 0.8 |
| `enum4linux` | enum4linux | SMB/NetBIOS enumeration | A05 | Windows/SMB | 0.7 |
| `interactsh` | Interactsh | OOB callback detection (blind SSRF, XXE, RCE) | Multiple | Web Apps | 0.7 |

## OWASP Top 10 Coverage

| OWASP Category | Modules |
|----------------|---------|
| **A01** Broken Access Control | acl, csrf, idor, redirect, path_traversal, discovery, crawler, cloud, sensitive, api, upload |
| **A02** Cryptographic Failures | ssl, sslyze, testssl, jwt, sensitive, trufflehog |
| **A03** Injection | injection, xss, cmdi, ssrf, xxe, nosql, ldap, ssti, crlf, sqlmap, dalfox |
| **A04** Insecure Design | api, mass_assignment, upload, arjun, paramspider |
| **A05** Security Misconfiguration | headers, misconfig, cors, csp, clickjacking, graphql, websocket, api_schema, smuggling, host_header, tech, dns, subdomain, waf, cname_takeover, vhost, cloud |
| **A06** Vulnerable Components | trivy, nuclei, wpscan, droopescan |
| **A07** Auth Failures | auth, ratelimit, jwt, hydra, dom_xss |
| **A08** Software Integrity | prototype_pollution |
| **A09** Logging/Monitoring | (detected via misconfig module) |
| **A10** SSRF | ssrf |

## Scan Profiles

| Profile | Modules | Use Case | Duration |
|---------|---------|----------|----------|
| `quick` | headers, tech, ssl, misconfig | Fast health check, CI/CD gate | ~5s |
| `standard` | All 35 built-in + available tools | Regular security assessment | ~30-60s |
| `thorough` | All 63 modules (built-in + all tools) | Full penetration test | ~5-15min |
