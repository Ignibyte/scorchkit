# Module Reference

ScorchKit ships **77 modules** organized into three categories:

| Category | Count | Description |
|----------|-------|-------------|
| Recon | 10 built-in | Passive and active reconnaissance |
| Scanner | 35 built-in | Vulnerability detection and security testing |
| Tool Wrappers | 32 external | Orchestrate third-party security tools |

All modules implement the `ScanModule` trait and are registered in
`src/runner/orchestrator.rs` via `all_modules()`.

---

## Table of Contents

- [Module Selection](#module-selection)
- [Scan Profiles](#scan-profiles)
- [Execution Model](#execution-model)
- [Inter-Module Data Sharing](#inter-module-data-sharing)
- [Recon Modules (10)](#recon-modules-10)
- [Scanner Modules (35)](#scanner-modules-35)
- [Tool Wrapper Modules (32)](#tool-wrapper-modules-32)

---

## Module Selection

### Run specific modules

```bash
scorchkit run https://target.com --modules headers,ssl,xss
```

### Skip modules

```bash
scorchkit run https://target.com --skip subdomain,crawler
```

### List all modules

```bash
scorchkit modules --check-tools
```

Module IDs are the short strings shown in the "Module ID" column of each
table below. Use these IDs with `--modules` and `--skip`.

---

## Scan Profiles

Profiles control which modules run. Set via `--profile <name>`.

### quick

Fast scan using only 4 built-in modules that require no external tools:

| Module ID | Name |
|-----------|------|
| `headers` | HTTP Security Headers |
| `tech` | Technology Fingerprinting |
| `ssl` | TLS/SSL Analysis |
| `misconfig` | Security Misconfiguration |

```bash
scorchkit run https://target.com --profile quick
```

### standard (default)

Runs all built-in modules (recon + scanner). External tool wrappers are
included but automatically skipped if the required tool is not installed.

```bash
scorchkit run https://target.com --profile standard
```

### thorough

Same as standard -- runs all modules. The thorough profile keeps all
registered modules including every external tool wrapper.

```bash
scorchkit run https://target.com --profile thorough
```

---

## Execution Model

### Concurrent execution via semaphore

Modules run concurrently up to `max_concurrent_modules` (configurable in
`config.toml`). A tokio `Semaphore` controls the concurrency limit.

Each module:
1. Acquires a semaphore permit
2. Executes its `run()` method
3. Releases the permit on completion
4. Reports success (findings) or error (skipped with reason)

### Phased execution with `run_phased`

For inter-module data sharing, the orchestrator supports two-phase
execution:

**Phase 1 -- Recon:** All modules with `category() == ModuleCategory::Recon`
run first. These publish discovered data (URLs, forms, technologies,
subdomains) to `SharedData`.

**Phase 2 -- Scanners:** All modules with `category() == ModuleCategory::Scanner`
run second. These can read shared data published by recon modules.

Within each phase, modules still run concurrently via the semaphore.

### Checkpoint / resume

The `run_with_checkpoint` method saves progress after each module
completes. If a scan is interrupted, it can resume from the checkpoint
file, skipping already-completed modules.

### External tool skipping

Before running a tool wrapper module, the orchestrator checks if the
required binary is installed (`which <tool>`). If not found, the module
is skipped with a message rather than failing the scan.

---

## Inter-Module Data Sharing

Modules communicate through `ScanContext::shared_data`, a thread-safe
key-value store (`RwLock<HashMap<String, Vec<String>>>`).

### Published keys

| Key | Published by | Contents |
|-----|-------------|----------|
| `urls` | Crawler (`crawler`) | Discovered page URLs |
| `forms` | Crawler (`crawler`) | Form action endpoint URLs |
| `params` | Crawler (`crawler`) | Query parameter names |
| `technologies` | Tech Fingerprinting (`tech`) | Detected technology names |
| `subdomains` | Subdomain Enumeration (`subdomain`) | Discovered subdomain hostnames |

### Consumers

| Module | Reads key | Purpose |
|--------|-----------|---------|
| SQL Injection (`injection`) | `urls` | Tests crawler-discovered URLs for SQLi |
| Reflected XSS (`xss`) | `urls` | Tests crawler-discovered URLs for XSS |

Phased execution ensures recon modules publish data before scanners
consume it.

---

## Recon Modules (10)

Recon modules perform reconnaissance -- discovering information about the
target without exploiting vulnerabilities.

### headers -- HTTP Security Headers

| | |
|---|---|
| **ID** | `headers` |
| **Category** | Recon |
| **External tool** | No |
| **Confidence** | 0.9 |
| **Description** | Analyze HTTP security headers (HSTS, CSP, X-Frame-Options, etc.) |

**Detects:** Missing or misconfigured security headers including
Strict-Transport-Security (HSTS), Content-Security-Policy (CSP),
X-Frame-Options, X-Content-Type-Options, Referrer-Policy,
Permissions-Policy, deprecated X-XSS-Protection usage, Server version
disclosure, and X-Powered-By information leakage.

**Example findings:**
- Missing Strict-Transport-Security (HSTS) Header (High)
- CSP Contains 'unsafe-inline' (Medium)
- Server Version Disclosure (Low)
- Missing Permissions-Policy Header (Info)

**Publishes:** Nothing  
**Consumes:** Nothing

---

### tech -- Technology Fingerprinting

| | |
|---|---|
| **ID** | `tech` |
| **Category** | Recon |
| **External tool** | No |
| **Confidence** | 0.7 |
| **Description** | Detect server technologies, frameworks, and CMS platforms |

**Detects:** Server software (Nginx, Apache, IIS, etc.), frameworks and
runtimes via X-Powered-By, CMS platforms via `<meta generator>` tags,
technology via cookie names (PHPSESSID, JSESSIONID, etc.), framework
signatures in response headers and body (WordPress, Drupal, React,
Next.js, Angular, Vue.js, etc.), and CMS indicators in asset paths.

**Example findings:**
- Server Technology Detected (Info)
- CMS/Framework Detected via Meta Generator (Info)
- Technology Detected via Cookie Names (Info)
- WordPress Detected via Asset Paths (Info)

**Publishes:** `technologies` -- list of detected technology names  
**Consumes:** Nothing

---

### discovery -- Directory & File Discovery

| | |
|---|---|
| **ID** | `discovery` |
| **Category** | Recon |
| **External tool** | No |
| **Confidence** | 0.6 |
| **Description** | Discover sensitive files, directories, and exposed endpoints |

**Detects:** Exposed source control directories (.git, .svn, .hg),
environment files (.env), config files, database dumps, admin panels
(WordPress, Joomla), debug endpoints (phpinfo, server-status, Spring
Boot Actuator), API documentation (Swagger, GraphQL), backup files, and
directory listings.

**Example findings:**
- Git Repository Exposed (Critical)
- Environment File Exposed (.env) (Critical)
- SQL Backup File Exposed (Critical)
- Directory Listing Enabled (Medium)
- robots.txt Found (Info)

**Publishes:** Nothing  
**Consumes:** Nothing

---

### subdomain -- Subdomain Enumeration

| | |
|---|---|
| **ID** | `subdomain` |
| **Category** | Recon |
| **External tool** | No |
| **Confidence** | 0.8 |
| **Description** | Enumerate subdomains via DNS brute-force with common wordlist |

**Detects:** Active subdomains via DNS resolution of a 64-entry wordlist
(www, mail, api, dev, staging, admin, git, jenkins, etc.). Flags
interesting subdomains such as internal/intranet (High), admin/staging/dev
(Medium), and infrastructure services like Jenkins, GitLab, Grafana.

**Example findings:**
- 12 Subdomains Discovered (Info)
- Interesting Subdomain: internal.example.com (High)
- Interesting Subdomain: staging.example.com (Medium)

**Publishes:** `subdomains` -- list of discovered subdomain hostnames  
**Consumes:** Nothing

---

### crawler -- Web Crawler

| | |
|---|---|
| **ID** | `crawler` |
| **Category** | Recon |
| **External tool** | No |
| **Confidence** | 0.5 |
| **Description** | Crawl the target to discover endpoints, forms, and parameters |

**Detects:** Pages, links, forms (with fields), URL parameters, JavaScript
files, and API routes extracted from inline scripts. Crawls up to 100
pages at a depth of 3. Stays in scope by domain. Avoids destructive
actions (logout, delete).

**Example findings:**
- Crawled 47 Pages (Info)
- Form Discovered: POST /login (Info)
- 15 URL Parameters Discovered (Info)

**Publishes:** `urls`, `forms`, `params` -- discovered URLs, form endpoints, and parameter names  
**Consumes:** Nothing

---

### dns-security -- DNS & Email Security

| | |
|---|---|
| **ID** | `dns-security` |
| **Category** | Recon |
| **External tool** | No |
| **Confidence** | 0.8 |
| **Description** | Check SPF, DMARC, DNSSEC, and MX records via DNS-over-HTTPS |

**Detects:** Missing or permissive SPF records (+all, ?all, ~all),
missing or unenforced DMARC policies (p=none), and MX record presence.
Uses Cloudflare DNS-over-HTTPS JSON API -- no DNS library required.

**Example findings:**
- No SPF Record: example.com (Medium)
- Permissive SPF Record: example.com (High)
- DMARC Policy Set to None: example.com (Medium)
- MX Records Found: example.com (Info)

**Publishes:** Nothing  
**Consumes:** Nothing

---

### js_analysis -- JavaScript File Analysis

| | |
|---|---|
| **ID** | `js_analysis` |
| **Category** | Recon |
| **External tool** | No |
| **Confidence** | 0.6 |
| **Description** | Extract secrets, API endpoints, and internal URLs from JavaScript files |

**Detects:** Hardcoded secrets in JS (AWS keys, Stripe keys, GitHub/GitLab
tokens, Slack tokens, Google API keys, Bearer tokens, private keys),
API endpoint patterns (/api/, /v1/, /admin/, /internal/, /debug/,
/swagger), and source map references that expose original source code.

**Example findings:**
- Secret in JS: AWS Access Key ID (Critical)
- Secret in JS: Stripe live secret key (Critical)
- API endpoints discovered in external JS file (Info)
- Source map reference detected (Medium)

**Publishes:** Nothing  
**Consumes:** Nothing

---

### cname_takeover -- CNAME Takeover & Cert Transparency

| | |
|---|---|
| **ID** | `cname_takeover` |
| **Category** | Recon |
| **External tool** | No |
| **Confidence** | 0.7 |
| **Description** | Detect dangling CNAME records and enumerate subdomains via crt.sh |

**Detects:** Dangling CNAME records pointing to deprovisioned services
(GitHub Pages, Heroku, AWS S3, Shopify, Tumblr, Fastly, Fly.io, Surge.sh,
Feedpress, Help Scout, JetBrains YouTrack). Also enumerates subdomains
via certificate transparency logs (crt.sh).

**Example findings:**
- Potential CNAME Takeover: GitHub Pages (High)
- Potential CNAME Takeover: AWS S3 (High)
- Certificate Transparency: 45 subdomains found (Info)

**Publishes:** Nothing  
**Consumes:** Nothing

---

### vhost -- Virtual Host Discovery

| | |
|---|---|
| **ID** | `vhost` |
| **Category** | Recon |
| **External tool** | No |
| **Confidence** | 0.6 |
| **Description** | Discover hidden virtual hosts via Host header brute-force |

**Detects:** Hidden virtual hosts by sending requests with modified Host
headers. Tests 35 common prefixes (admin, api, staging, internal, dev,
dashboard, etc.) and compares response size and status code against a
baseline to identify unique vhosts.

**Example findings:**
- 3 virtual hosts discovered (Info)

**Publishes:** Nothing  
**Consumes:** Nothing

---

### cloud -- Cloud Metadata & Bucket Enumeration

| | |
|---|---|
| **ID** | `cloud` |
| **Category** | Recon |
| **External tool** | No |
| **Confidence** | 0.7 |
| **Description** | Detect cloud provider, check metadata endpoints, enumerate storage buckets |

**Detects:** Cloud provider from response headers (AWS, Google Cloud,
Azure, Cloudflare, DigitalOcean, Vercel, Netlify, Fly.io). Enumerates
S3 buckets derived from the domain name with 19 suffix variations
(-assets, -backup, -data, -dev, -staging, etc.).

**Example findings:**
- Cloud provider detected: AWS, Cloudflare (Info)
- 3 cloud storage buckets found (High if public, Medium if 403)

**Publishes:** Nothing  
**Consumes:** Nothing

---

## Scanner Modules (35)

Scanner modules actively test for vulnerabilities. They send crafted
requests and analyze responses to identify security issues.

### auth-session -- Auth & Session Management

| | |
|---|---|
| **ID** | `auth-session` |
| **Category** | Scanner |
| **External tool** | No |
| **Confidence** | 0.7 |
| **Description** | Test session ID entropy, fixation, logout invalidation, and expiry |

**Example findings:**
- Weak Session ID Entropy (High)
- Session Fixation Vulnerability (High)
- Session Not Invalidated After Logout (Medium)

---

### cors-deep -- CORS Deep Analysis

| | |
|---|---|
| **ID** | `cors-deep` |
| **Category** | Scanner |
| **External tool** | No |
| **Confidence** | 0.9 |
| **Description** | Deep CORS testing: subdomain wildcards, preflight cache, method allowlists, internal origins |

**Example findings:**
- CORS Reflects Subdomain Wildcard (High)
- Permissive Preflight Cache (Medium)
- CORS Allows Internal Origin (Medium)

---

### csp-deep -- CSP Bypass Detection

| | |
|---|---|
| **ID** | `csp-deep` |
| **Category** | Scanner |
| **External tool** | No |
| **Confidence** | 0.9 |
| **Description** | Deep CSP analysis: missing directives, permissive script-src, report-uri leaks |

**Example findings:**
- CSP Missing script-src Directive (Medium)
- CSP Allows Unsafe Script Sources (High)
- CSP report-uri Leaks Internal Hostname (Low)

---

### waf -- WAF Detection

| | |
|---|---|
| **ID** | `waf` |
| **Category** | Scanner |
| **External tool** | No |
| **Confidence** | 0.7 |
| **Description** | Detect Web Application Firewalls via response analysis |

**Example findings:**
- WAF Detected: Cloudflare (Info)
- WAF Detected via Block Response (Info)
- No WAF Detected (Info)

---

### ssl -- TLS/SSL Analysis

| | |
|---|---|
| **ID** | `ssl` |
| **Category** | Scanner |
| **External tool** | No |
| **Confidence** | 0.9 |
| **Description** | Analyze TLS/SSL certificate and configuration |

**Detects:** Missing TLS encryption (plain HTTP), expired or soon-expiring
certificates, self-signed certificates, weak signature algorithms
(SHA-1, MD5), and certificate subject/SAN mismatches.

**Example findings:**
- No TLS/SSL Encryption (High)
- Certificate Expired (Critical)
- Self-Signed Certificate (High)
- Weak Certificate Signature Algorithm (Medium)

---

### misconfig -- Security Misconfiguration

| | |
|---|---|
| **ID** | `misconfig` |
| **Category** | Scanner |
| **External tool** | No |
| **Confidence** | 0.8 |
| **Description** | Check CORS, cookie flags, error pages, and HTTP methods |

**Detects:** CORS misconfiguration (arbitrary origin reflection, wildcard
with credentials), insecure cookie flags (missing HttpOnly, Secure,
SameSite), verbose error pages disclosing stack traces, and dangerous
HTTP methods (PUT, DELETE, TRACE).

**Example findings:**
- CORS Reflects Arbitrary Origin with Credentials (Critical)
- Cookie Missing HttpOnly Flag (Medium)
- Verbose Error Page Disclosing Stack Trace (Medium)
- Dangerous HTTP Method Enabled: PUT (Medium)

---

### csrf -- CSRF Detection

| | |
|---|---|
| **ID** | `csrf` |
| **Category** | Scanner |
| **External tool** | No |
| **Confidence** | 0.7 |
| **Description** | Detect missing CSRF protection on state-changing forms |

**Example findings:**
- POST Form Missing CSRF Token (Medium)

---

### injection -- SQL Injection Detection

| | |
|---|---|
| **ID** | `injection` |
| **Category** | Scanner |
| **External tool** | No |
| **Confidence** | 0.8 |
| **Description** | Detect SQL injection via error-based testing of URL parameters and forms |

**Detects:** Error-based SQL injection by injecting SQL metacharacters
into URL parameters and form fields. Detects database-specific error
messages (MySQL, PostgreSQL, MSSQL, Oracle, SQLite). Tests parameters in
the target URL, spidered links, and discovered forms.

**Example findings:**
- SQL Injection: Error-Based (Critical)
- SQL Injection in Form Parameter (Critical)

**Consumes:** `urls` from crawler

---

### cmdi -- Command Injection Detection

| | |
|---|---|
| **ID** | `cmdi` |
| **Category** | Scanner |
| **External tool** | No |
| **Confidence** | 0.8 |
| **Description** | Detect OS command injection via parameter fuzzing |

**Example findings:**
- OS Command Injection Detected (Critical)
- Potential Blind Command Injection (High)

---

### xss -- Reflected XSS Detection

| | |
|---|---|
| **ID** | `xss` |
| **Category** | Scanner |
| **External tool** | No |
| **Confidence** | 0.8 |
| **Description** | Detect reflected cross-site scripting (XSS) via canary injection |

**Detects:** Reflected XSS by injecting canary strings into URL
parameters, spidered links, and form fields. Tests for unescaped
reflection of HTML special characters.

**Example findings:**
- Reflected XSS: Unescaped Input (High)
- XSS in Form Parameter (High)

**Consumes:** `urls` from crawler

---

### ssrf -- SSRF Detection

| | |
|---|---|
| **ID** | `ssrf` |
| **Category** | Scanner |
| **External tool** | No |
| **Confidence** | 0.7 |
| **Description** | Detect Server-Side Request Forgery (SSRF) via URL parameter injection |

**Example findings:**
- SSRF: Internal Address Accessible (Critical)
- Potential SSRF in URL Parameter (High)

---

### xxe -- XXE Detection

| | |
|---|---|
| **ID** | `xxe` |
| **Category** | Scanner |
| **External tool** | No |
| **Confidence** | 0.7 |
| **Description** | Detect XML External Entity injection on XML-accepting endpoints |

**Detects:** XXE by sending crafted XML payloads to common endpoints
(/api, /xmlrpc.php, /soap, /wsdl, /upload). Tests for entity expansion
and external entity processing.

**Example findings:**
- XXE: External Entity Processed (Critical)
- XXE: Entity Expansion Detected (High)

---

### idor -- IDOR Detection

| | |
|---|---|
| **ID** | `idor` |
| **Category** | Scanner |
| **External tool** | No |
| **Confidence** | 0.5 |
| **Description** | Detect Insecure Direct Object References by manipulating IDs |

**Example findings:**
- Potential IDOR: Sequential ID Access (Medium)
- Potential IDOR: Different Object Returned (Medium)

---

### jwt -- JWT Analysis

| | |
|---|---|
| **ID** | `jwt` |
| **Category** | Scanner |
| **External tool** | No |
| **Confidence** | 0.8 |
| **Description** | Analyze JWT tokens in responses for security weaknesses |

**Detects:** Weak JWT algorithms (none, HS256 with known secrets),
missing expiration claims, excessive token lifetimes, sensitive data in
payloads, and algorithm confusion vulnerabilities.

**Example findings:**
- JWT Uses "none" Algorithm (Critical)
- JWT Missing Expiration Claim (Medium)
- JWT Contains Sensitive Data (Medium)
- JWT Weak HMAC Secret (High)

---

### redirect -- Open Redirect Detection

| | |
|---|---|
| **ID** | `redirect` |
| **Category** | Scanner |
| **External tool** | No |
| **Confidence** | 0.8 |
| **Description** | Detect open redirect vulnerabilities in URL parameters |

**Example findings:**
- Open Redirect via URL Parameter (Medium)

---

### sensitive -- Sensitive Data Exposure

| | |
|---|---|
| **ID** | `sensitive` |
| **Category** | Scanner |
| **External tool** | No |
| **Confidence** | 0.7 |
| **Description** | Detect exposed API keys, secrets, and PII in responses |

**Example findings:**
- API Key Exposed in Response (High)
- Email Addresses in Response (Low)
- Credit Card Number Pattern (High)

---

### api-schema -- API Schema Discovery

| | |
|---|---|
| **ID** | `api-schema` |
| **Category** | Scanner |
| **External tool** | No |
| **Confidence** | 0.7 |
| **Description** | Discover exposed OpenAPI/Swagger specs and GraphQL schemas |

**Example findings:**
- OpenAPI/Swagger Specification Exposed (Low)
- GraphQL Schema Exposed via Introspection (Low)

---

### ratelimit -- Rate Limit Testing

| | |
|---|---|
| **ID** | `ratelimit` |
| **Category** | Scanner |
| **External tool** | No |
| **Confidence** | 0.6 |
| **Description** | Test authentication endpoints for brute-force protection |

**Example findings:**
- No Rate Limiting on Login Endpoint (Medium)
- Rate Limiting Detected (Info)

---

### upload -- File Upload Testing

| | |
|---|---|
| **ID** | `upload` |
| **Category** | Scanner |
| **External tool** | No |
| **Confidence** | 0.6 |
| **Description** | Test file upload endpoints for unrestricted types, bypasses, and dangerous content |

**Example findings:**
- Unrestricted File Upload: Executable Accepted (Critical)
- File Upload Bypass via Double Extension (High)

---

### websocket -- WebSocket Security

| | |
|---|---|
| **ID** | `websocket` |
| **Category** | Scanner |
| **External tool** | No |
| **Confidence** | 0.7 |
| **Description** | Test WebSocket endpoints for CSWSH, unencrypted transport, and auth bypass |

**Example findings:**
- Cross-Site WebSocket Hijacking (CSWSH) (High)
- WebSocket Over Unencrypted Transport (Medium)
- WebSocket Missing Authentication (Medium)

---

### graphql -- GraphQL Security

| | |
|---|---|
| **ID** | `graphql` |
| **Category** | Scanner |
| **External tool** | No |
| **Confidence** | 0.7 |
| **Description** | Test GraphQL for introspection, depth abuse, batching, and field suggestion leaks |

**Example findings:**
- GraphQL Introspection Enabled (Medium)
- GraphQL Query Depth Abuse (Medium)
- GraphQL Batching Enabled (Low)
- GraphQL Field Suggestion Leak (Low)

---

### subtakeover -- Subdomain Takeover

| | |
|---|---|
| **ID** | `subtakeover` |
| **Category** | Scanner |
| **External tool** | No |
| **Confidence** | 0.8 |
| **Description** | Detect subdomain takeover via cloud provider fingerprint matching |

**Example findings:**
- Subdomain Takeover: S3 Bucket (High)
- Subdomain Takeover: GitHub Pages (High)

---

### acl -- Access Control Testing

| | |
|---|---|
| **ID** | `acl` |
| **Category** | Scanner |
| **External tool** | No |
| **Confidence** | 0.6 |
| **Description** | Test for admin path exposure, method override bypass, and forced browsing |

**Example findings:**
- Admin Path Accessible Without Auth (High)
- HTTP Method Override Bypass (Medium)
- Forced Browsing: Sequential Resource Access (Medium)

---

### api-security -- API Security (OWASP Top 10)

| | |
|---|---|
| **ID** | `api-security` |
| **Category** | Scanner |
| **External tool** | No |
| **Confidence** | 0.7 |
| **Description** | Test REST APIs for mass assignment, data exposure, shadow APIs, and rate limiting |

**Example findings:**
- API Mass Assignment Vulnerability (High)
- Excessive Data Exposure in API Response (Medium)
- Shadow API Endpoint Discovered (Medium)
- API Missing Rate Limiting (Medium)

---

### path_traversal -- Path Traversal / LFI Detection

| | |
|---|---|
| **ID** | `path_traversal` |
| **Category** | Scanner |
| **External tool** | No |
| **Confidence** | 0.8 |
| **Description** | Detect path traversal and local file inclusion vulnerabilities |

**Example findings:**
- Path Traversal: /etc/passwd Accessible (Critical)
- Local File Inclusion via Parameter (High)

---

### ssti -- SSTI Detection

| | |
|---|---|
| **ID** | `ssti` |
| **Category** | Scanner |
| **External tool** | No |
| **Confidence** | 0.8 |
| **Description** | Detect server-side template injection across multiple template engines |

**Example findings:**
- Server-Side Template Injection Detected (Critical)
- SSTI: Template Expression Evaluated (Critical)

---

### crlf -- CRLF Injection Detection

| | |
|---|---|
| **ID** | `crlf` |
| **Category** | Scanner |
| **External tool** | No |
| **Confidence** | 0.9 |
| **Description** | Detect CRLF injection and HTTP response splitting vulnerabilities |

**Example findings:**
- CRLF Injection: HTTP Response Splitting (High)

---

### host_header -- Host Header Injection Detection

| | |
|---|---|
| **ID** | `host_header` |
| **Category** | Scanner |
| **External tool** | No |
| **Confidence** | 0.8 |
| **Description** | Detect host header injection for cache poisoning and password reset attacks |

**Example findings:**
- Host Header Injection: Reflected in Response (High)
- Host Header Injection: Password Reset Poisoning (High)

---

### nosql -- NoSQL Injection Detection

| | |
|---|---|
| **ID** | `nosql` |
| **Category** | Scanner |
| **External tool** | No |
| **Confidence** | 0.7 |
| **Description** | Detect NoSQL injection via MongoDB operator and JSON body injection |

**Example findings:**
- NoSQL Injection: MongoDB Operator Injection (Critical)
- NoSQL Injection: JSON Body Injection (Critical)

---

### ldap -- LDAP Injection Detection

| | |
|---|---|
| **ID** | `ldap` |
| **Category** | Scanner |
| **External tool** | No |
| **Confidence** | 0.7 |
| **Description** | Detect LDAP injection via filter metacharacter injection |

**Example findings:**
- LDAP Injection: Filter Metacharacter Processed (High)
- LDAP Injection: Boolean Blind (High)

---

### smuggling -- HTTP Request Smuggling Detection

| | |
|---|---|
| **ID** | `smuggling` |
| **Category** | Scanner |
| **External tool** | No |
| **Confidence** | 0.5 |
| **Description** | Detect HTTP request smuggling risk via proxy detection and TE handling analysis |

**Example findings:**
- HTTP Request Smuggling Risk: CL.TE Desync (High)
- HTTP Request Smuggling Risk: TE.CL Desync (High)
- Transfer-Encoding Handling Anomaly (Medium)

---

### prototype_pollution -- Prototype Pollution Detection

| | |
|---|---|
| **ID** | `prototype_pollution` |
| **Category** | Scanner |
| **External tool** | No |
| **Confidence** | 0.5 |
| **Description** | Detect prototype pollution via __proto__ and constructor property injection |

**Example findings:**
- Prototype Pollution via __proto__ Query Parameter (High)
- Prototype Pollution via constructor.prototype (High)
- Prototype Pollution via JSON Body (High)

---

### mass_assignment -- Mass Assignment Detection

| | |
|---|---|
| **ID** | `mass_assignment` |
| **Category** | Scanner |
| **External tool** | No |
| **Confidence** | 0.6 |
| **Description** | Detect mass assignment via extra privileged field injection in JSON bodies |

**Example findings:**
- Mass Assignment: Privileged Field Accepted (High)

---

### clickjacking -- Clickjacking Detection

| | |
|---|---|
| **ID** | `clickjacking` |
| **Category** | Scanner |
| **External tool** | No |
| **Confidence** | 0.9 |
| **Description** | Detect clickjacking via missing X-Frame-Options and CSP frame-ancestors |

**Example findings:**
- Clickjacking: No Frame Protection (Medium)

---

### dom_xss -- DOM XSS Detection

| | |
|---|---|
| **ID** | `dom_xss` |
| **Category** | Scanner |
| **External tool** | No |
| **Confidence** | 0.4 |
| **Description** | Detect DOM-based XSS via static JavaScript source/sink analysis |

**Example findings:**
- DOM XSS: Dangerous Source/Sink Combination (Medium)
- DOM XSS: innerHTML with User Input (Medium)

---

## Tool Wrapper Modules (32)

Tool wrapper modules orchestrate external security tools. Each requires
the named binary to be installed. If the tool is not found in `$PATH`,
the module is automatically skipped.

### interactsh -- Interactsh OOB Detection

| | |
|---|---|
| **ID** | `interactsh` |
| **Category** | Scanner |
| **External tool** | `interactsh-client` |
| **Confidence** | 0.7 |
| **Description** | Detect blind SSRF, XXE, RCE, and SQLi via out-of-band callbacks |

**Example findings:**
- Out-of-Band Callback Received (Critical)

---

### nmap -- Nmap Port Scanner

| | |
|---|---|
| **ID** | `nmap` |
| **Category** | Scanner |
| **External tool** | `nmap` |
| **Confidence** | 0.9 |
| **Description** | Port scanning and service detection via nmap |

**Example findings:**
- Open Ports Discovered (Info)
- Service Detected: Apache httpd 2.4.52 on port 80 (Info)

---

### nuclei -- Nuclei Vulnerability Scanner

| | |
|---|---|
| **ID** | `nuclei` |
| **Category** | Scanner |
| **External tool** | `nuclei` |
| **Confidence** | 0.8 |
| **Description** | Template-based vulnerability scanning via nuclei |

**Example findings:**
- Nuclei: CVE-2021-44228 Log4Shell (Critical)
- Nuclei: Exposed Admin Panel (Medium)

---

### nikto -- Nikto Web Scanner

| | |
|---|---|
| **ID** | `nikto` |
| **Category** | Scanner |
| **External tool** | `nikto` |
| **Confidence** | 0.6 |
| **Description** | Web server vulnerability scanning via nikto |

**Example findings:**
- Nikto: Outdated Server Version (Medium)
- Nikto: Dangerous HTTP Method (Medium)

---

### sqlmap -- SQLMap Injection Scanner

| | |
|---|---|
| **ID** | `sqlmap` |
| **Category** | Scanner |
| **External tool** | `sqlmap` |
| **Confidence** | 0.9 |
| **Description** | Automated SQL injection detection via sqlmap |

**Example findings:**
- SQLMap: SQL Injection Confirmed (Critical)
- SQLMap: Blind SQL Injection (High)

---

### feroxbuster -- Feroxbuster Directory Scanner

| | |
|---|---|
| **ID** | `feroxbuster` |
| **Category** | Recon |
| **External tool** | `feroxbuster` |
| **Confidence** | 0.6 |
| **Description** | Recursive directory and content discovery via feroxbuster |

**Example findings:**
- Feroxbuster: Discovered Path /admin/config (Low)

---

### sslyze -- SSLyze TLS Analyzer

| | |
|---|---|
| **ID** | `sslyze` |
| **Category** | Scanner |
| **External tool** | `sslyze` |
| **Confidence** | 0.9 |
| **Description** | Comprehensive TLS/SSL configuration analysis via sslyze |

**Example findings:**
- SSLyze: SSLv3 Enabled (Critical)
- SSLyze: Weak Cipher Suite (High)
- SSLyze: Missing OCSP Stapling (Low)
- SSLyze: Certificate Expiring Soon (Medium)

---

### zap -- OWASP ZAP Scanner

| | |
|---|---|
| **ID** | `zap` |
| **Category** | Scanner |
| **External tool** | `zap-cli` |
| **Confidence** | 0.7 |
| **Description** | Active web application scanning via OWASP ZAP |

**Example findings:**
- ZAP: Cross-Site Scripting (High)
- ZAP: SQL Injection (High)

---

### ffuf -- ffuf Web Fuzzer

| | |
|---|---|
| **ID** | `ffuf` |
| **Category** | Recon |
| **External tool** | `ffuf` |
| **Confidence** | 0.6 |
| **Description** | Fast content discovery and fuzzing via ffuf |

**Example findings:**
- ffuf: Discovered Endpoint /api/internal (Low)

---

### metasploit -- Metasploit Scanner

| | |
|---|---|
| **ID** | `metasploit` |
| **Category** | Scanner |
| **External tool** | `msfconsole` |
| **Confidence** | 0.9 |
| **Description** | Exploit validation via Metasploit auxiliary modules |

**Example findings:**
- Metasploit: Vulnerability Confirmed (Critical)
- Metasploit: Exploit Module Match (High)

---

### wafw00f -- WAF Detection (wafw00f)

| | |
|---|---|
| **ID** | `wafw00f` |
| **Category** | Recon |
| **External tool** | `wafw00f` |
| **Confidence** | 0.7 |
| **Description** | Web Application Firewall detection via wafw00f |

**Example findings:**
- WAF Detected: Cloudflare (Info)
- WAF Detected: ModSecurity (Info)
- No WAF Detected (Info)

---

### testssl -- testssl.sh TLS Analyzer

| | |
|---|---|
| **ID** | `testssl` |
| **Category** | Scanner |
| **External tool** | `testssl.sh` |
| **Confidence** | 0.9 |
| **Description** | Comprehensive TLS/SSL testing via testssl.sh |

**Example findings:**
- testssl: Vulnerable to Heartbleed (Critical)
- testssl: TLS 1.0 Enabled (Medium)

---

### wpscan -- WPScan WordPress Scanner

| | |
|---|---|
| **ID** | `wpscan` |
| **Category** | Scanner |
| **External tool** | `wpscan` |
| **Confidence** | 0.8 |
| **Description** | WordPress vulnerability scanning via WPScan |

**Example findings:**
- WPScan: WordPress Version Outdated (Medium)
- WPScan: Vulnerable Plugin Detected (High)
- WPScan: Vulnerable Theme Detected (High)

---

### amass -- Amass Subdomain Enumerator

| | |
|---|---|
| **ID** | `amass` |
| **Category** | Recon |
| **External tool** | `amass` |
| **Confidence** | 0.8 |
| **Description** | Advanced subdomain enumeration via OWASP Amass |

**Example findings:**
- Amass: Subdomains Discovered (Info)

---

### subfinder -- Subfinder

| | |
|---|---|
| **ID** | `subfinder` |
| **Category** | Recon |
| **External tool** | `subfinder` |
| **Confidence** | 0.8 |
| **Description** | Fast passive subdomain discovery via Subfinder |

**Example findings:**
- Subfinder: Subdomains Discovered (Info)

---

### dalfox -- Dalfox XSS Scanner

| | |
|---|---|
| **ID** | `dalfox` |
| **Category** | Scanner |
| **External tool** | `dalfox` |
| **Confidence** | 0.8 |
| **Description** | Advanced XSS scanning via Dalfox |

**Example findings:**
- Dalfox: XSS Confirmed (High)

---

### hydra -- Hydra Login Tester

| | |
|---|---|
| **ID** | `hydra` |
| **Category** | Scanner |
| **External tool** | `hydra` |
| **Confidence** | 0.9 |
| **Description** | Default credential testing via Hydra |

**Example findings:**
- Hydra: Default Credentials Found (Critical)

---

### httpx -- httpx HTTP Prober

| | |
|---|---|
| **ID** | `httpx` |
| **Category** | Recon |
| **External tool** | `httpx` |
| **Confidence** | 0.8 |
| **Description** | HTTP technology probing via httpx |

**Example findings:**
- httpx: Technology Fingerprint (Info)

---

### theharvester -- theHarvester OSINT

| | |
|---|---|
| **ID** | `theharvester` |
| **Category** | Recon |
| **External tool** | `theHarvester` |
| **Confidence** | 0.6 |
| **Description** | Email and subdomain harvesting via theHarvester |

**Example findings:**
- theHarvester: Email Addresses Discovered (Info)
- theHarvester: Subdomains Discovered (Info)

---

### arjun -- Arjun Parameter Discovery

| | |
|---|---|
| **ID** | `arjun` |
| **Category** | Recon |
| **External tool** | `arjun` |
| **Confidence** | 0.7 |
| **Description** | Hidden HTTP parameter discovery via Arjun |

**Example findings:**
- Arjun: Hidden Parameters Discovered (Low)

---

### cewl -- CeWL Wordlist Generator

| | |
|---|---|
| **ID** | `cewl` |
| **Category** | Recon |
| **External tool** | `cewl` |
| **Confidence** | 0.5 |
| **Description** | Custom wordlist generation from target content via CeWL |

**Example findings:**
- CeWL: Custom Wordlist Generated (Info)

---

### droopescan -- Droopescan CMS Scanner

| | |
|---|---|
| **ID** | `droopescan` |
| **Category** | Scanner |
| **External tool** | `droopescan` |
| **Confidence** | 0.7 |
| **Description** | CMS vulnerability scanning (Drupal, Joomla, WordPress, Silverstripe) |

**Example findings:**
- Droopescan: CMS Version Detected (Medium)
- Droopescan: Vulnerable Plugin (High)
- Droopescan: Default Theme (Low)

---

### katana -- Katana Web Crawler

| | |
|---|---|
| **ID** | `katana` |
| **Category** | Recon |
| **External tool** | `katana` |
| **Confidence** | 0.7 |
| **Description** | JS-rendering web crawler for comprehensive endpoint discovery |

**Example findings:**
- Katana: Endpoints Discovered (Info)

---

### gau -- Gau Passive URLs

| | |
|---|---|
| **ID** | `gau` |
| **Category** | Recon |
| **External tool** | `gau` |
| **Confidence** | 0.6 |
| **Description** | Passive URL discovery from Wayback Machine, Common Crawl, and other sources |

**Example findings:**
- Gau: Historical URLs Discovered (Info)

---

### paramspider -- ParamSpider Parameter Miner

| | |
|---|---|
| **ID** | `paramspider` |
| **Category** | Recon |
| **External tool** | `paramspider` |
| **Confidence** | 0.6 |
| **Description** | Mine URLs with query parameters for injection point discovery |

**Example findings:**
- ParamSpider: Parameterized URLs Discovered (Info)

---

### trufflehog -- Trufflehog Secret Scanner

| | |
|---|---|
| **ID** | `trufflehog` |
| **Category** | Scanner |
| **External tool** | `trufflehog` |
| **Confidence** | 0.8 |
| **Description** | Secret scanning for API keys, credentials, and tokens via Trufflehog |

**Example findings:**
- Trufflehog: Secret Detected (High)

---

### prowler -- Prowler Cloud Scanner

| | |
|---|---|
| **ID** | `prowler` |
| **Category** | Scanner |
| **External tool** | `prowler` |
| **Confidence** | 0.8 |
| **Description** | Cloud infrastructure security assessment via Prowler (AWS, Azure, GCP) |

**Example findings:**
- Prowler: Cloud Misconfiguration (High)
- Prowler: Security Check Failed (Medium)

---

### trivy -- Trivy Vulnerability Scanner

| | |
|---|---|
| **ID** | `trivy` |
| **Category** | Scanner |
| **External tool** | `trivy` |
| **Confidence** | 0.8 |
| **Description** | Container image and dependency vulnerability scanning via Trivy |

**Example findings:**
- Trivy: CVE-2023-XXXXX in package (High)

---

### dnsx -- DNSx DNS Toolkit

| | |
|---|---|
| **ID** | `dnsx` |
| **Category** | Recon |
| **External tool** | `dnsx` |
| **Confidence** | 0.8 |
| **Description** | Fast DNS resolution, wildcard detection, and record queries via DNSx |

**Example findings:**
- DNSx: DNS Records Enumerated (Info)

---

### gobuster -- Gobuster Directory Scanner

| | |
|---|---|
| **ID** | `gobuster` |
| **Category** | Recon |
| **External tool** | `gobuster` |
| **Confidence** | 0.6 |
| **Description** | Directory and vhost brute-forcing via Gobuster |

**Example findings:**
- Gobuster: Discovered Path /backup (Low)

---

### dnsrecon -- dnsrecon DNS Enumerator

| | |
|---|---|
| **ID** | `dnsrecon` |
| **Category** | Recon |
| **External tool** | `dnsrecon` |
| **Confidence** | 0.8 |
| **Description** | Comprehensive DNS enumeration: zone transfers, reverse lookups, SRV records via dnsrecon |

**Example findings:**
- dnsrecon: Zone Transfer Possible (High)
- dnsrecon: DNS Records Enumerated (Info)

---

### enum4linux -- enum4linux SMB Enumerator

| | |
|---|---|
| **ID** | `enum4linux` |
| **Category** | Scanner |
| **External tool** | `enum4linux` |
| **Confidence** | 0.7 |
| **Description** | SMB share, user, group, and password policy enumeration via enum4linux |

**Example findings:**
- enum4linux: SMB Shares Discovered (Medium)
- enum4linux: Users Enumerated (Medium)
- enum4linux: Weak Password Policy (Medium)
