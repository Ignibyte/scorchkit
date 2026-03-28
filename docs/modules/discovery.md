# Directory & File Discovery

**Module ID:** `discovery` | **Category:** Recon | **Type:** Built-in
**Source:** `src/recon/discovery.rs`

## What It Does

Probes the target for sensitive files, exposed directories, debug endpoints, admin panels, backup files, and API documentation. The module sends HTTP requests to 28 known-sensitive paths and checks responses against content markers and status codes. It also includes soft 404 detection to reduce false positives and scans for directory listing on common asset directories.

## Checks Performed

### Source Control Exposure (3 probes)

| Path | Title | Severity | Detection Method |
|------|-------|----------|-----------------|
| `/.git/HEAD` | Git Repository Exposed | Critical | 200 + body contains `ref:` |
| `/.svn/entries` | SVN Repository Exposed | Critical | 200 OK |
| `/.hg/store/00manifest.i` | Mercurial Repository Exposed | Critical | 200 OK |

### Environment & Config Files (4 probes)

| Path | Title | Severity | Detection Method |
|------|-------|----------|-----------------|
| `/.env` | Environment File Exposed | Critical | 200 + body does NOT contain `<!DOCTYPE` |
| `/.env.backup` | Environment Backup File Exposed | Critical | 200 + body does NOT contain `<!DOCTYPE` |
| `/config.php` | PHP Config File Accessible | High | 200 + body does NOT contain `<!DOCTYPE` |
| `/wp-config.php.bak` | WordPress Config Backup Exposed | Critical | 200 + body contains `DB_` |

### Informational Files (4 probes)

| Path | Title | Severity | Detection Method |
|------|-------|----------|-----------------|
| `/robots.txt` | robots.txt Found | Info | 200 + body contains `isallow` |
| `/sitemap.xml` | sitemap.xml Found | Info | 200 + body contains `<?xml` |
| `/.well-known/security.txt` | security.txt Found | Info | 200 + body contains `Contact` |
| `/security.txt` | security.txt Found (root) | Info | 200 + body contains `Contact` |

### Admin Panels (4 probes)

| Path | Title | Severity | Detection Method |
|------|-------|----------|-----------------|
| `/admin` | Admin Panel Found | Low | Any status except 404/410/405 |
| `/wp-admin/` | WordPress Admin Panel Found | Low | Any status except 404/410/405 |
| `/administrator/` | Joomla Admin Panel Found | Low | Any status except 404/410/405 |
| `/wp-login.php` | WordPress Login Page Exposed | Info | 200 OK |

### Debug & Status Endpoints (7 probes)

| Path | Title | Severity | Detection Method |
|------|-------|----------|-----------------|
| `/server-status` | Apache server-status Exposed | Medium | 200 + body contains `Apache Server Status` |
| `/server-info` | Apache server-info Exposed | High | 200 + body contains `Apache Server Information` |
| `/phpinfo.php` | phpinfo() Page Exposed | High | 200 + body contains `phpinfo()` |
| `/info.php` | PHP Info Page Exposed | High | 200 + body contains `phpinfo()` |
| `/debug` | Debug Endpoint Found | Medium | 200 OK |
| `/elmah.axd` | ELMAH Error Log Exposed (ASP.NET) | High | 200 OK |
| `/actuator/health` | Spring Boot Actuator Exposed | Medium | 200 + body contains `status` |

### Backup & Database Files (3 probes)

| Path | Title | Severity | Detection Method |
|------|-------|----------|-----------------|
| `/backup.sql` | SQL Backup File Exposed | Critical | 200 + body contains `INSERT INTO` |
| `/database.sql` | Database Dump Exposed | Critical | 200 + body contains `CREATE TABLE` |
| `/dump.sql` | Database Dump Exposed | Critical | 200 + body contains `CREATE TABLE` |

### API Documentation (3 probes)

| Path | Title | Severity | Detection Method |
|------|-------|----------|-----------------|
| `/swagger-ui.html` | Swagger UI Exposed | Low | 200 OK |
| `/api-docs` | API Documentation Exposed | Low | 200 OK |
| `/graphql` | GraphQL Endpoint Found | Low | Any status except 404/410/405 |

### Directory Listing Detection

Tests 5 common asset paths (`/icons/`, `/images/`, `/assets/`, `/static/`, `/uploads/`) for directory listing. Detects Apache-style (`Index of`), Nginx-style, and IIS-style (`[To Parent Directory]`) directory listings. Stops after the first positive match.

### Soft 404 Detection

Responses that return HTTP 200 but contain phrases like "page not found", "does not exist", or "could not be found" are filtered out as false positives -- unless the body specifically references the probed path.

## Findings

| Title | Severity | Description |
|-------|----------|-------------|
| Git Repository Exposed | Critical | Full source code and history downloadable via .git |
| SVN Repository Exposed | Critical | Source code exposed via .svn directory |
| Mercurial Repository Exposed | Critical | Source code exposed via .hg directory |
| Environment File Exposed (.env) | Critical | Database credentials, API keys, secrets accessible |
| Environment Backup File Exposed | Critical | Backup .env file containing secrets accessible |
| PHP Config File Accessible | High | config.php may expose database credentials |
| WordPress Config Backup Exposed | Critical | wp-config.php backup exposes database credentials |
| robots.txt Found | Info | May reveal hidden paths |
| sitemap.xml Found | Info | Reveals site URL structure |
| security.txt Found | Info | Responsible disclosure policy present |
| Admin Panel Found | Low | Admin interface publicly accessible |
| WordPress Admin Panel Found | Low | wp-admin accessible |
| Joomla Admin Panel Found | Low | Joomla administrator panel accessible |
| WordPress Login Page Exposed | Info | Login page publicly accessible |
| Apache server-status Exposed | Medium | Server load, uptime, requests revealed |
| Apache server-info Exposed | High | Full server configuration exposed |
| phpinfo() Page Exposed | High | PHP version, config, and environment exposed |
| Debug Endpoint Found | Medium | Application internals potentially exposed |
| ELMAH Error Log Exposed (ASP.NET) | High | Stack traces and errors visible |
| Spring Boot Actuator Exposed | Medium | Application health and config revealed |
| SQL Backup File Exposed | Critical | Entire database potentially downloadable |
| Database Dump Exposed | Critical | Database dump file accessible |
| Swagger UI Exposed | Low | All API endpoints documented publicly |
| API Documentation Exposed | Low | API documentation publicly accessible |
| GraphQL Endpoint Found | Low | Schema introspection may reveal full API |
| Directory Listing Enabled | Medium | File structure exposed to attackers |

## OWASP Coverage

- **A05:2021 -- Security Misconfiguration**: Exposed config files, debug endpoints, server-status, directory listing, source control exposure, phpinfo, actuator endpoints
- **A01:2021 -- Broken Access Control**: Accessible admin panels and unrestricted management interfaces
- **A07:2021 -- Identification and Authentication Failures**: Exposed login pages

### CWE References

| CWE | Name | Applies To |
|-----|------|------------|
| CWE-538 | Insertion of Sensitive Information into Externally-Accessible File | .git, .svn, .hg exposure |
| CWE-200 | Exposure of Sensitive Information to an Unauthorized Actor | .env files, config files, phpinfo, server-status, backup files, API docs |
| CWE-284 | Improper Access Control | Admin panels |
| CWE-548 | Exposure of Information Through Directory Listing | Directory listing enabled |
| CWE-215 | Insertion of Sensitive Information Into Debugging Code | Debug endpoints |

## How It Works

1. Resolves the target's base URL (scheme + host, no path).
2. Iterates over 28 static probe definitions, each specifying a path, expected detection condition, severity, and metadata.
3. For each probe, sends a GET request and evaluates the response using one of four check strategies:
   - **StatusOk**: HTTP 200 returned (with soft 404 filtering).
   - **StatusOkWithContent(marker)**: HTTP 200 and body contains the specified marker string.
   - **StatusOkNoContent(forbidden)**: HTTP 200 and body does NOT contain the forbidden marker (filters out HTML error pages).
   - **AnyNon404**: Any status code except 404, 410, or 405.
4. Positive matches include a 200-character body preview as evidence.
5. After all probes complete, tests 5 common directories for directory listing using Apache, Nginx, and IIS signature detection.

## Example Output

```
[CRITICAL] Git Repository Exposed
  URL: https://example.com/.git/HEAD
  The .git directory is accessible. The entire source code and commit history
  may be downloadable.
  Evidence: HTTP 200 at https://example.com/.git/HEAD | Body preview: ref: refs/heads/main
  Remediation: Block access to .git/ in your web server configuration
  OWASP: A05:2021 Security Misconfiguration
  CWE: 538

[CRITICAL] Environment File Exposed (.env)
  URL: https://example.com/.env
  The .env file is accessible. It typically contains database credentials,
  API keys, and other secrets.
  Evidence: HTTP 200 at https://example.com/.env | Body preview: DB_HOST=localhost DB_USER=root...
  Remediation: Block access to .env files in your web server configuration
  OWASP: A05:2021 Security Misconfiguration
  CWE: 200

[MEDIUM] Directory Listing Enabled
  URL: https://example.com/images/
  Directory listing is enabled at https://example.com/images/. This exposes
  the file structure to attackers.
  Evidence: Response contains directory index markers
  Remediation: Disable directory listing in your web server configuration
  OWASP: A05:2021 Security Misconfiguration
  CWE: 548
```
