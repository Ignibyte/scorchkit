# CSP Bypass Detection

**Module ID:** `csp-deep` | **Category:** Scanner | **Type:** Built-in
**Source:** `src/scanner/csp.rs`

## What It Does

Analyzes Content-Security-Policy headers for bypass-prone configurations. Complements the `headers` recon module (which checks for CSP presence, `unsafe-inline`, `unsafe-eval`, and wildcard) with deeper directive analysis: missing critical directives, permissive `script-src` sources, weak `default-src` fallbacks, and `report-uri` information leaks.

## Checks Performed

| Check | Description |
|-------|-------------|
| Missing critical directives | Checks for `base-uri`, `object-src`, and `frame-ancestors` |
| Permissive script-src | Detects `data:`, `blob:`, `https:`, `http:` in script-src (or default-src fallback) |
| Permissive default-src | Flags `default-src *` which negates CSP entirely |
| Report URI leak | Detects `report-uri` and `report-to` endpoints that expose internal infrastructure |

## Findings

| Finding | Severity | CWE | Trigger |
|---------|----------|-----|---------|
| Missing base-uri Directive | Medium | 693 | CSP lacks `base-uri`, enabling `<base>` tag injection for script redirect |
| Missing object-src Directive | Medium | 693 | CSP lacks `object-src` and `default-src` is not restrictive |
| Missing frame-ancestors Directive | Medium | 1021 | CSP lacks `frame-ancestors`, enabling clickjacking |
| Permissive script-src: data: | High | 693 | `script-src` allows `data:` URIs for inline script execution |
| Permissive script-src: blob: | High | 693 | `script-src` allows `blob:` URIs for dynamic script creation |
| Permissive script-src: https: | High | 693 | `script-src` allows any HTTPS origin including attacker CDNs |
| Permissive script-src: http: | High | 693 | `script-src` allows any HTTP origin, negating CSP |
| Permissive default-src: wildcard | High | 693 | `default-src *` allows resources from any origin |
| CSP Report URI Reveals Internal Infrastructure | Low | 200 | `report-uri` exposes monitoring/security tooling URLs |
| CSP Report-To Endpoint Configured | Low | 200 | `report-to` directive present (may expose infrastructure via Reporting-API) |

## OWASP Coverage

**A05:2021 -- Security Misconfiguration.** Covers CSP bypass techniques via missing directives, overly permissive source lists, and information disclosure through reporting endpoints.

## How It Works

1. **Fetch CSP**: Retrieves the `Content-Security-Policy` header from the target. If absent, returns no findings (CSP presence is handled by `recon/headers.rs`).
2. **Parse directives**: Splits the CSP by semicolons into a directive map (`directive-name -> [sources]`). All keys and values are lowercased.
3. **Missing directives**: Checks for `base-uri`, `object-src`, and `frame-ancestors`. For `object-src`, a restrictive `default-src` (`'none'` or `'self'`) is accepted as a fallback. `frame-ancestors` has no fallback and is always required.
4. **Permissive script-src**: Checks `script-src` (falling back to `default-src`) for dangerous sources: `data:`, `blob:`, `https:`, and `http:` protocol-based allowlists.
5. **Report leak**: Extracts `report-uri` endpoint URLs that reveal internal hostnames or paths. Also flags `report-to` usage.

## Example Output

```
[High] Permissive script-src: data:
  The CSP script-src allows 'data:'. data: URIs allow inline script execution
  via <script src="data:text/javascript,...">
  Evidence: script-src includes 'data:'
  Remediation: Remove 'data:' from script-src. Use nonces or hashes for inline scripts.
  OWASP: A05:2021 Security Misconfiguration | CWE-693
```
