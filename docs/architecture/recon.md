# Recon Modules

Reconnaissance modules gather information about the target without active exploitation. They live in `src/recon/`.

## Files

```
recon/
  mod.rs         Module registration (6 modules)
  headers.rs     HTTP security header analysis
  tech.rs        Technology fingerprinting
  discovery.rs   Directory/endpoint discovery
  subdomain.rs   Subdomain enumeration via DNS brute-force
  crawler.rs     Web crawler for endpoint/form/parameter discovery
  dns.rs         DNS and email security checks via DoH
```

## Registration

`recon/mod.rs` declares submodules and registers them:

```rust
mod crawler;
mod discovery;
mod dns;
mod headers;
mod subdomain;
mod tech;

pub fn register_modules() -> Vec<Box<dyn ScanModule>> {
    vec![
        Box::new(headers::HeadersModule),
        Box::new(tech::TechModule),
        Box::new(discovery::DiscoveryModule),
        Box::new(subdomain::SubdomainModule),
        Box::new(crawler::CrawlerModule),
        Box::new(dns::DnsSecurityModule),
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

## Tech Fingerprinting (`tech.rs`)

**ID:** `tech`
**Name:** Technology Fingerprinting
**Category:** Recon
**External tool:** None (built-in)
**Description:** Detect server technologies, frameworks, and CMS platforms

Detects server technologies by analyzing:
- `Server` header value
- `X-Powered-By` header
- HTML `<meta name="generator">` tags
- Cookie name patterns (JSESSIONID -> Java, PHPSESSID -> PHP, etc.)
- Response body framework signatures
- Common file paths (/wp-admin -> WordPress, etc.)

## Directory Discovery (`discovery.rs`)

**ID:** `discovery`
**Name:** Directory & File Discovery
**Category:** Recon
**External tool:** None (built-in)
**Description:** Discover sensitive files, directories, and exposed endpoints

Checks a wordlist of common sensitive paths:
- `/.git/HEAD`, `/.env`, `/robots.txt`, `/sitemap.xml`
- `/admin`, `/wp-admin`, `/.well-known/security.txt`
- `/server-status`, `/server-info`, `/phpinfo.php`

## Subdomain Enumeration (`subdomain.rs`)

**ID:** `subdomain`
**Name:** Subdomain Enumeration
**Category:** Recon
**External tool:** None (built-in)
**Description:** Enumerate subdomains via DNS brute-force with common wordlist

Enumerates subdomains of the target domain by DNS-resolving common subdomain prefixes (www, mail, api, admin, etc.) against the target domain. Reports discovered subdomains as informational findings. Requires the target to have a domain (IP targets are skipped).

## Web Crawler (`crawler.rs`)

**ID:** `crawler`
**Name:** Web Crawler
**Category:** Recon
**External tool:** None (built-in)
**Description:** Crawl the target to discover endpoints, forms, and parameters

Crawls the target starting from the root URL, following links up to depth 3 and visiting up to 100 pages. Discovers endpoints, forms, and URL parameters by parsing HTML with the `scraper` crate. Stays within the target domain boundary.

## DNS & Email Security (`dns.rs`)

**ID:** `dns-security`
**Name:** DNS & Email Security
**Category:** Recon
**External tool:** None (built-in, uses DNS-over-HTTPS)
**Description:** Check SPF, DMARC, DNSSEC, and MX records via DNS-over-HTTPS

Queries DNS records via Cloudflare's DNS-over-HTTPS JSON API to check:
- **SPF** - Permissive `+all` or missing SPF records
- **DMARC** - Missing or weak policy enforcement (`p=none`)
- **DNSSEC** - Whether DNSSEC validation is enabled
- **MX** - Presence and configuration of mail exchange records

Uses the existing `reqwest` HTTP client for DoH queries, requiring no DNS crate dependency.
