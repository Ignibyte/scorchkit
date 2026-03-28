# WAF Detection

**Module ID:** `waf` | **Category:** Recon | **Type:** Built-in
**Source:** `src/scanner/waf.rs`

## What It Does

Detects the presence of Web Application Firewalls (WAFs) protecting the target by analyzing response headers from a normal request and then triggering WAF block pages with a crafted attack probe. Identifying a WAF early in a scan helps contextualize other findings and indicates that certain attack vectors may be filtered or blocked.

## Checks Performed

### Phase 1: Header-Based Detection (11 WAF headers)

Examines response headers from a normal GET request to the target:

| Header | WAF Identified |
|--------|---------------|
| `cf-ray` | Cloudflare |
| `cf-cache-status` | Cloudflare |
| `x-sucuri-id` | Sucuri |
| `x-sucuri-cache` | Sucuri |
| `server` | (checked against 8 known WAF patterns -- see below) |
| `x-powered-by-plesk` | Plesk |
| `x-cdn` | CDN/WAF (value used as name) |
| `x-akamai-transformed` | Akamai |
| `x-barracuda-waf` | Barracuda WAF |
| `x-denied-reason` | Generic WAF |
| `x-dotdefender-denied` | dotDefender |

#### Server Header WAF Patterns (8 signatures)

When the `server` header is present, it is checked against these patterns:

| Pattern | WAF Identified |
|---------|---------------|
| `cloudflare` | Cloudflare |
| `akamai` | Akamai |
| `incapsula` | Imperva Incapsula |
| `sucuri` | Sucuri |
| `barracuda` | Barracuda |
| `f5 big-ip` | F5 BIG-IP |
| `fortiweb` | FortiWeb |
| `wallarm` | Wallarm |

### Phase 2: Attack Probe Trigger

Sends a crafted request designed to trigger WAF detection rules:

```
GET {target}?id=1'+OR+1=1--&<script>alert(1)</script>
```

This payload combines SQL injection and XSS patterns to maximize the chance of triggering a WAF block response. The module checks for HTTP 403, 406, or 429 status codes in the response.

### Phase 3: Body-Based Detection (16 WAF signatures)

If the attack probe returns a block status code, the response body is scanned for WAF-identifying content:

| Body Pattern | WAF Identified |
|-------------|---------------|
| `cloudflare` | Cloudflare |
| `attention required` | Cloudflare |
| `sucuri website firewall` | Sucuri |
| `access denied - sucuri` | Sucuri |
| `incapsula` | Imperva Incapsula |
| `request unsuccessful` | Imperva |
| `modsecurity` | ModSecurity |
| `not acceptable` | ModSecurity |
| `wordfence` | Wordfence |
| `blocked by wordfence` | Wordfence |
| `akamai` | Akamai |
| `access denied` | Generic WAF |
| `web application firewall` | Generic WAF |
| `waf` | Generic WAF |
| `blocked` | Generic WAF |
| `forbidden` | Possible WAF |

### Phase 4: Generic WAF Fallback

If no specific WAF is identified but the attack probe returns HTTP 403 with an `x-request-id` header present, a generic "Possible WAF/Rate Limiter" finding is generated.

## Findings

| Title | Severity | Description |
|-------|----------|-------------|
| WAF Detected: {name} | Info | Specific WAF identified via headers (Phase 1) |
| WAF Detected: {name} | Info | Specific WAF identified via block page content (Phase 3) |
| Possible WAF/Rate Limiter | Info | Generic 403 response to attack probe suggests WAF presence |

All WAF detection findings use **Info** severity. The module avoids duplicate findings -- if a WAF is detected via headers, the same WAF will not be reported again from the body analysis.

## OWASP Coverage

WAF detection is an informational reconnaissance step that does not directly map to OWASP Top 10 categories. However, knowing the WAF in use is relevant to:

- **A05:2021 -- Security Misconfiguration**: Verifying that WAF is properly deployed
- **A09:2021 -- Security Logging and Monitoring Failures**: WAFs provide logging and monitoring capabilities

## How It Works

1. **Normal request**: Sends a standard GET request to the target URL and examines response headers against 11 known WAF header signatures. The `server` header gets special handling, checked against 8 additional WAF-specific patterns. Detection stops at the first match to avoid duplicate findings.

2. **Attack probe**: Constructs a URL with SQL injection (`1'+OR+1=1--`) and XSS (`<script>alert(1)</script>`) payloads in the query string. Sends a GET request to this URL.

3. **Block page analysis**: If the attack probe returns HTTP 403, 406, or 429, the response body is scanned (case-insensitive) against 16 WAF signature strings. The first match is reported. Findings already generated from header analysis are not duplicated.

4. **Fallback detection**: If no specific WAF is identified but the attack probe returned 403 with an `x-request-id` header, a generic WAF/rate limiter finding is generated.

## Example Output

```
[INFO] WAF Detected: Cloudflare
  URL: https://example.com/
  Web Application Firewall detected: Cloudflare
  Evidence: cf-ray: 8a1b2c3d4e5f6g7h-IAD

[INFO] WAF Detected: ModSecurity
  URL: https://example.com/
  ModSecurity detected via block response (HTTP 403)
  Evidence: HTTP 403 on attack probe | Body contains 'modsecurity'

[INFO] Possible WAF/Rate Limiter
  URL: https://example.com/
  HTTP 403 returned on attack probe, suggesting WAF or rate limiting
  Evidence: HTTP 403 on malicious input
```
