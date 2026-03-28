# Scanner Modules

Scanner modules perform active vulnerability detection. They live in `src/scanner/`.

## Files

```
scanner/
  mod.rs          Module registration (currently returns empty vec)
  ssl.rs          TLS/SSL configuration analysis (Phase 4)
  misconfig.rs    Security misconfiguration checks (Phase 4)
  injection.rs    SQL injection detection (Phase 4)
  xss.rs          Reflected XSS detection (Phase 4)
```

## Registration

```rust
pub fn register_modules() -> Vec<Box<dyn ScanModule>> {
    // Scanner modules will be added in Phase 4
    vec![]
}
```

## Planned: SSL Module (`ssl.rs`)

**ID:** `ssl`
**Category:** Scanner
**OWASP:** A02:2021 Cryptographic Failures

Built-in checks:
- Certificate validity and expiration (days until expiry)
- Certificate chain completeness
- Protocol version support (flag TLS 1.0, 1.1 as deprecated)
- Common name / SAN mismatch
- Self-signed certificate detection

External tool wrapper:
- `sslyze` or `testssl.sh` for comprehensive cipher suite and protocol analysis
- Parse JSON output from sslyze, or terminal output from testssl

## Planned: Misconfig Module (`misconfig.rs`)

**ID:** `misconfig`
**Category:** Scanner
**OWASP:** A05:2021 Security Misconfiguration

Checks:
- **CORS misconfiguration** - Send requests with `Origin: https://evil.com`, check if `Access-Control-Allow-Origin` reflects it or is `*`
- **Cookie security flags** - Check `Set-Cookie` headers for missing `Secure`, `HttpOnly`, `SameSite` attributes
- **Error page information disclosure** - Request non-existent paths, check if error pages reveal framework, version, stack traces
- **Directory listing** - Check if directory URLs return file listings
- **HTTP methods** - Send OPTIONS request, check for dangerous methods (PUT, DELETE, TRACE)
- **Default credentials** - Check common admin paths with default creds (configurable, off by default)

## Planned: Injection Module (`injection.rs`)

**ID:** `injection`
**Category:** Scanner
**OWASP:** A03:2021 Injection

Two modes:

**Built-in (basic error-based detection):**
1. Spider the target for forms and URL parameters
2. Inject common SQL metacharacters (`'`, `"`, `; --`, `' OR '1'='1`)
3. Check responses for SQL error strings:
   - MySQL: `You have an error in your SQL syntax`
   - PostgreSQL: `ERROR: syntax error`
   - MSSQL: `Unclosed quotation mark`
   - SQLite: `SQLITE_ERROR`
   - Generic: `SQL syntax`, `mysql_fetch`, `pg_query`
4. Compare response lengths/status codes between clean and injected requests

**External (sqlmap wrapper):**
- Pass discovered injection points to sqlmap for confirmation
- Parse sqlmap's JSON output for confirmed vulnerabilities
- Configurable risk/level parameters

## Planned: XSS Module (`xss.rs`)

**ID:** `xss`
**Category:** Scanner
**OWASP:** A03:2021 Injection

**Detection method:**
1. Spider the target for URL parameters and form inputs
2. Inject a unique canary string (e.g., `scorch<test>"'`)
3. Check if the canary appears in the response body without encoding
4. If reflected: test with actual XSS payloads (`<script>`, event handlers)
5. Check if reflected payload is inside HTML context, attribute context, or JavaScript context
6. Flag appropriate severity based on context and encoding

**Checks:**
- Reflected XSS in URL parameters
- Reflected XSS in form inputs
- DOM-based XSS indicators (check for `document.write`, `innerHTML`, `eval` with user-controlled data)
