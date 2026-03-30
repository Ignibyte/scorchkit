# Scanner Modules

Scanner modules perform active vulnerability detection. They live in `src/scanner/`.

## Files

```
scanner/
  mod.rs          Module registration (24 modules)
  ssl.rs          TLS/SSL configuration analysis
  misconfig.rs    Security misconfiguration checks
  csrf.rs         CSRF protection detection
  injection.rs    SQL injection detection
  cmdi.rs         OS command injection detection
  xss.rs          Reflected XSS detection
  ssrf.rs         Server-Side Request Forgery detection
  xxe.rs          XML External Entity injection detection
  idor.rs         Insecure Direct Object Reference detection
  jwt.rs          JWT token security analysis
  redirect.rs     Open redirect detection
  sensitive.rs    Sensitive data exposure detection
  api_schema.rs   API schema discovery (OpenAPI/GraphQL)
  ratelimit.rs    Rate limiting / brute-force protection testing
  cors.rs         Deep CORS policy analysis
  csp.rs          CSP bypass detection
  auth.rs         Authentication & session management testing
  upload.rs       File upload vulnerability testing
  websocket.rs    WebSocket security testing
  graphql.rs      GraphQL deep security testing
  subtakeover.rs  Subdomain takeover detection
  acl.rs          Access control / authorization bypass testing
  api.rs          REST API security testing (OWASP API Top 10)
  waf.rs          Built-in WAF detection
```

## Registration

```rust
pub fn register_modules() -> Vec<Box<dyn ScanModule>> {
    vec![
        Box::new(auth::AuthSessionModule),
        Box::new(cors::CorsModule),
        Box::new(csp::CspModule),
        Box::new(waf::WafModule),
        Box::new(ssl::SslModule),
        Box::new(misconfig::MisconfigModule),
        Box::new(csrf::CsrfModule),
        Box::new(injection::InjectionModule),
        Box::new(cmdi::CmdiModule),
        Box::new(xss::XssModule),
        Box::new(ssrf::SsrfModule),
        Box::new(xxe::XxeModule),
        Box::new(idor::IdorModule),
        Box::new(jwt::JwtModule),
        Box::new(redirect::RedirectModule),
        Box::new(sensitive::SensitiveDataModule),
        Box::new(upload::UploadModule),
        Box::new(websocket::WebSocketModule),
        Box::new(graphql::GraphQLModule),
        Box::new(subtakeover::SubdomainTakeoverModule),
        Box::new(acl::AclModule),
        Box::new(api::ApiSecurityModule),
        Box::new(api_schema::ApiSchemaModule),
        Box::new(ratelimit::RateLimitModule),
    ]
}
```

## Module Reference

### auth-session (`auth.rs`)

**ID:** `auth-session`
**Name:** Auth & Session Management
**Category:** Scanner
**Description:** Test session ID entropy, fixation, logout invalidation, and expiry

Tests session lifecycle security: session ID entropy, session fixation (pre/post-auth cookie comparison), logout invalidation, session expiry analysis, and multiple session cookie detection. Complements `misconfig` which tests cookie attributes (`Secure`, `HttpOnly`, `SameSite`). Credential-gated tests require `AuthConfig` to be configured.

### cors-deep (`cors.rs`)

**ID:** `cors-deep`
**Name:** CORS Deep Analysis
**Category:** Scanner
**Description:** Deep CORS testing: subdomain wildcards, preflight cache, method allowlists, internal origins

Tests CORS configurations beyond the basic origin reflection checks in `misconfig`. Analyzes subdomain wildcard patterns, preflight cache duration, overly permissive method/header allowlists, sensitive header exposure, and internal network origin acceptance.

### csp-deep (`csp.rs`)

**ID:** `csp-deep`
**Name:** CSP Bypass Detection
**Category:** Scanner
**Description:** Deep CSP analysis: missing directives, permissive script-src, report-uri leaks

Analyzes CSP headers for bypass-prone configurations beyond the basic checks in `recon::headers`. Tests for missing critical directives, overly permissive `script-src`, `report-uri` information leaks, and weak `default-src` fallbacks.

### waf (`waf.rs`)

**ID:** `waf`
**Name:** WAF Detection
**Category:** Recon
**Description:** Detect Web Application Firewalls via response analysis

Built-in WAF detection without external tools. Analyzes HTTP responses for signatures indicating the presence of a Web Application Firewall.

### ssl (`ssl.rs`)

**ID:** `ssl`
**Name:** TLS/SSL Analysis
**Category:** Scanner
**Description:** Analyze TLS/SSL certificate and configuration

Analyzes TLS/SSL configuration of the target. Checks certificate validity and expiration, certificate chain completeness, protocol version support (flags TLS 1.0/1.1 as deprecated), CN/SAN mismatch, and self-signed certificate detection.

### misconfig (`misconfig.rs`)

**ID:** `misconfig`
**Name:** Security Misconfiguration
**Category:** Scanner
**Description:** Check CORS, cookie flags, error pages, and HTTP methods
**OWASP:** A05:2021 Security Misconfiguration

Checks CORS origin reflection, cookie security flags (`Secure`, `HttpOnly`, `SameSite`), error page information disclosure, directory listing, and dangerous HTTP methods (PUT, DELETE, TRACE).

### csrf (`csrf.rs`)

**ID:** `csrf`
**Name:** CSRF Detection
**Category:** Scanner
**Description:** Detect missing CSRF protection on state-changing forms

Parses HTML to find forms using POST/PUT/DELETE methods and checks for CSRF token presence in hidden fields or meta tags.

### injection (`injection.rs`)

**ID:** `injection`
**Name:** SQL Injection Detection
**Category:** Scanner
**Description:** Detect SQL injection via error-based testing of URL parameters and forms
**OWASP:** A03:2021 Injection

Detects potential SQL injection vulnerabilities by injecting SQL metacharacters into URL parameters and form inputs, then checking responses for SQL error strings across multiple database engines.

### cmdi (`cmdi.rs`)

**ID:** `cmdi`
**Name:** Command Injection Detection
**Category:** Scanner
**Description:** Detect OS command injection via parameter fuzzing

Tests URL parameters with OS command injection payloads, looking for command execution indicators in responses.

### xss (`xss.rs`)

**ID:** `xss`
**Name:** Reflected XSS Detection
**Category:** Scanner
**Description:** Detect reflected cross-site scripting (XSS) via canary injection
**OWASP:** A03:2021 Injection

Injects unique canary strings into URL parameters and form inputs, then checks if the canary appears in the response without encoding. Tests HTML context, attribute context, and JavaScript context reflection.

### ssrf (`ssrf.rs`)

**ID:** `ssrf`
**Name:** SSRF Detection
**Category:** Scanner
**Description:** Detect Server-Side Request Forgery (SSRF) via URL parameter injection

Tests URL parameters that accept URL-like values by injecting internal network addresses and cloud metadata URLs, checking for indicators of server-side request processing.

### xxe (`xxe.rs`)

**ID:** `xxe`
**Name:** XXE Detection
**Category:** Scanner
**Description:** Detect XML External Entity injection on XML-accepting endpoints

Probes endpoints that accept XML content types, injecting XXE payloads to test for entity expansion and external entity inclusion.

### idor (`idor.rs`)

**ID:** `idor`
**Name:** IDOR Detection
**Category:** Scanner
**Description:** Detect Insecure Direct Object References by manipulating IDs

Tests URL path segments and parameters containing numeric or UUID-like identifiers by manipulating them to detect unauthorized access to other objects.

### jwt (`jwt.rs`)

**ID:** `jwt`
**Name:** JWT Analysis
**Category:** Scanner
**Description:** Analyze JWT tokens in responses for security weaknesses

Discovers JWT tokens in responses and cookies, then analyzes them for security issues: algorithm confusion (none/HS256), missing expiry, excessive lifetime, weak secrets, and information disclosure in claims.

### redirect (`redirect.rs`)

**ID:** `redirect`
**Name:** Open Redirect Detection
**Category:** Scanner
**Description:** Detect open redirect vulnerabilities in URL parameters

Tests URL parameters for open redirect vulnerabilities by injecting external URLs and checking if the server issues a redirect to the injected destination.

### sensitive (`sensitive.rs`)

**ID:** `sensitive`
**Name:** Sensitive Data Exposure
**Category:** Scanner
**Description:** Detect exposed API keys, secrets, and PII in responses

Scans HTML responses and JavaScript files for exposed secrets, API keys, credentials, and PII patterns using regex matching.

### upload (`upload.rs`)

**ID:** `upload`
**Name:** File Upload Testing
**Category:** Scanner
**Description:** Test file upload endpoints for unrestricted types, bypasses, and dangerous content

Discovers upload forms via HTML parsing (`<input type="file">`), then submits test payloads to probe for unrestricted file type acceptance, double extension bypass, content-type mismatch, polyglot files, null byte injection, path traversal in filenames, and dangerous content uploads (SVG XSS, HTML).

### websocket (`websocket.rs`)

**ID:** `websocket`
**Name:** WebSocket Security
**Category:** Scanner
**Description:** Test WebSocket endpoints for CSWSH, unencrypted transport, and auth bypass

Probes common WebSocket endpoint paths, tests for Cross-Site WebSocket Hijacking (CSWSH) via origin validation, detects unencrypted `ws://` connections, and checks for unauthenticated WebSocket access.

### graphql (`graphql.rs`)

**ID:** `graphql`
**Name:** GraphQL Security
**Category:** Scanner
**Description:** Test GraphQL for introspection, depth abuse, batching, and field suggestion leaks

Tests GraphQL endpoints for introspection exposure, query depth/complexity abuse, batch query abuse, field suggestion information leaks, and mutation enumeration. Complements `api-schema` (Recon) with active security testing.

### subtakeover (`subtakeover.rs`)

**ID:** `subtakeover`
**Name:** Subdomain Takeover
**Category:** Scanner
**Description:** Detect subdomain takeover via cloud provider fingerprint matching

Generates common subdomain URLs from the target domain, fetches each, and checks response bodies against known cloud provider error pages that indicate an unclaimed resource available for takeover.

### acl (`acl.rs`)

**ID:** `acl`
**Name:** Access Control Testing
**Category:** Scanner
**Description:** Test for admin path exposure, method override bypass, and forced browsing

Probes for common authorization bypass patterns: admin path discovery, HTTP method override bypass, verb tampering, path traversal bypass variants, and forced browsing to predictable resource IDs. All tests are non-destructive.

### api-security (`api.rs`)

**ID:** `api-security`
**Name:** API Security (OWASP Top 10)
**Category:** Scanner
**Description:** Test REST APIs for mass assignment, data exposure, shadow APIs, and rate limiting

Tests API-specific vulnerabilities based on OWASP API Top 10: mass assignment, excessive data exposure, shadow API discovery, API rate limiting, and content negotiation confusion. Complements `acl` (BOLA/forced browsing) and `injection` (generic SQL/command injection).

### api-schema (`api_schema.rs`)

**ID:** `api-schema`
**Name:** API Schema Discovery
**Category:** Recon
**Description:** Discover exposed OpenAPI/Swagger specs and GraphQL schemas

Discovers and analyzes exposed API schema files by probing common paths for OpenAPI/Swagger JSON files and GraphQL introspection endpoints.

### ratelimit (`ratelimit.rs`)

**ID:** `ratelimit`
**Name:** Rate Limit Testing
**Category:** Scanner
**Description:** Test authentication endpoints for brute-force protection

Tests whether authentication endpoints have rate limiting or brute-force protection by sending rapid requests and checking for lockout, CAPTCHA, or rate-limit headers.
