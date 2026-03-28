# Recon Modules

Reconnaissance modules gather information about the target without active exploitation. They live in `src/recon/`.

## Files

```
recon/
  mod.rs         Module registration
  headers.rs     HTTP security header analysis (implemented)
  tech.rs        Technology fingerprinting (Phase 3)
  discovery.rs   Directory/endpoint discovery (Phase 3)
```

## Registration

`recon/mod.rs` declares submodules and registers them:

```rust
mod headers;

pub fn register_modules() -> Vec<Box<dyn ScanModule>> {
    vec![
        Box::new(headers::HeadersModule),
    ]
}
```

New recon modules: add `mod my_module;` and `Box::new(my_module::MyModule)` to the vec.

## Headers Module (`headers.rs`)

**ID:** `headers`
**Category:** Recon
**External tool:** None (built-in)

Makes a single GET request to the target URL and analyzes response headers for security misconfigurations.

### Checks Performed

| Check | Header | Severity | CWE | Description |
|-------|--------|----------|-----|-------------|
| HSTS missing | `Strict-Transport-Security` | High | 319 | No HTTPS enforcement |
| HSTS weak max-age | `Strict-Transport-Security` | Low | - | max-age < 1 year (31536000s) |
| HSTS no includeSubDomains | `Strict-Transport-Security` | Info | - | Subdomains not covered |
| CSP missing | `Content-Security-Policy` | Medium | 693 | No XSS/injection protection |
| CSP unsafe-inline | `Content-Security-Policy` | Medium | 693 | Weakens XSS protection |
| CSP unsafe-eval | `Content-Security-Policy` | Medium | 693 | Allows dynamic code execution |
| CSP wildcard | `Content-Security-Policy` | Medium | - | Allows any origin |
| X-Frame-Options missing | `X-Frame-Options` | Medium | 1021 | Clickjacking risk (checks CSP frame-ancestors as fallback) |
| X-Content-Type-Options missing | `X-Content-Type-Options` | Low | 693 | MIME sniffing risk |
| Referrer-Policy missing | `Referrer-Policy` | Low | - | URL/query param leakage |
| Referrer-Policy weak | `Referrer-Policy` | Low | - | `unsafe-url` or `no-referrer-when-downgrade` |
| Permissions-Policy missing | `Permissions-Policy` | Info | - | Browser features unrestricted |
| X-XSS-Protection active | `X-XSS-Protection` | Info | - | Deprecated header still in use |
| Server version disclosure | `Server` | Low | 200 | Version info in Server header |
| X-Powered-By disclosure | `X-Powered-By` | Low | 200 | Technology stack revealed |

All findings reference **OWASP A05:2021 Security Misconfiguration**.

### Helper Functions

- `extract_max_age(hsts_value) -> Option<u64>` - Parses the max-age directive from an HSTS header value
- `has_csp_frame_ancestors(headers) -> bool` - Checks if CSP includes a frame-ancestors directive (suppresses X-Frame-Options finding if present)

## Planned: Tech Fingerprinting (`tech.rs`)

**ID:** `tech`
**Category:** Recon

Will detect server technologies by analyzing:
- `Server` header value
- `X-Powered-By` header
- HTML `<meta name="generator">` tags
- Cookie name patterns (JSESSIONID → Java, PHPSESSID → PHP, etc.)
- Response body framework signatures
- Common file paths (/wp-admin → WordPress, etc.)

## Planned: Directory Discovery (`discovery.rs`)

**ID:** `discovery`
**Category:** Recon

Two modes:
1. **Built-in** - checks a small wordlist of common sensitive paths:
   - `/.git/HEAD`, `/.env`, `/robots.txt`, `/sitemap.xml`
   - `/admin`, `/wp-admin`, `/.well-known/security.txt`
   - `/server-status`, `/server-info`, `/phpinfo.php`
2. **External** - wraps `feroxbuster` for deep recursive directory brute-forcing
