# SSRF Detection

**Module ID:** `ssrf` | **Category:** Scanner | **Type:** Built-in
**Source:** `src/scanner/ssrf.rs`

## What It Does

Detects Server-Side Request Forgery vulnerabilities by injecting internal network addresses and cloud metadata URLs into parameters that appear to accept URLs. It identifies URL-like parameters through name heuristics and value analysis, then checks whether the server fetches the injected target by looking for internal resource indicators in the response.

## Checks Performed

### SSRF Payloads (10)

| # | Payload | Target |
|---|---------|--------|
| 1 | `http://127.0.0.1` | Localhost |
| 2 | `http://localhost` | Localhost (hostname) |
| 3 | `http://[::1]` | IPv6 localhost |
| 4 | `http://169.254.169.254/latest/meta-data/` | AWS EC2 metadata |
| 5 | `http://metadata.google.internal/computeMetadata/v1/` | GCP metadata |
| 6 | `http://169.254.169.254/metadata/instance` | Azure metadata |
| 7 | `http://127.0.0.1:22` | Localhost SSH port |
| 8 | `http://127.0.0.1:3306` | Localhost MySQL port |
| 9 | `http://10.0.0.1` | Internal 10.x range |
| 10 | `http://192.168.1.1` | Internal 192.168.x range |

### URL-like Parameter Detection

Parameters are considered URL-accepting if their name contains any of: `url`, `uri`, `link`, `href`, `src`, `source`, `dest`, `destination`, `redirect`, `return`, `next`, `target`, `rurl`, `return_url`, `redirect_uri`, `callback`, `continue`, `image`, `img`, `fetch`, `proxy`, `load`

Or if their value starts with `http://`, `https://`, or `//`.

### Response Indicators

| Indicator | Meaning |
|-----------|---------|
| `ami-id`, `instance-id`, `security-credentials`, `iam` | AWS metadata was fetched |
| `root:x:0:0` | `/etc/passwd` content (file read via SSRF) |
| `[global]` | Configuration file content |

## Findings

| Finding | Severity | CWE | Trigger |
|---------|----------|-----|---------|
| Potential SSRF in Parameter | Critical | 918 | Response contains internal resource indicators |
| SSRF Probe Caused Server Error | Medium | 918 | Internal URL injection caused HTTP 500 |

## OWASP Coverage

**A10:2021 -- Server-Side Request Forgery.** Covers SSRF via internal IP ranges, cloud metadata services (AWS, GCP, Azure), and internal port scanning.

## How It Works

1. **Parameter discovery:** The target page is fetched and its links are parsed with `scraper`. Parameters whose names or values suggest URL acceptance are identified.
2. **Own parameter testing:** The target URL's own query parameters are also checked against the URL-like heuristic.
3. **Payload injection:** For each candidate parameter, the 10 SSRF payloads are injected sequentially, replacing the original value.
4. **Response analysis:** The `contains_ssrf_indicator` function checks the response body for cloud metadata identifiers (`ami-id`, `instance-id`, etc.) when the payload targeted 169.254.169.254, and for generic internal content markers (`root:x:0:0`, `[global]`) otherwise.
5. **500 detection:** If no indicator is found but the response returns HTTP 500, a Medium finding is emitted.
6. **Early termination:** Testing stops at the first confirmed finding per parameter.

## Example Output

```
[Critical] Potential SSRF in Parameter: imageUrl
  The parameter 'imageUrl' may be vulnerable to SSRF. Injecting AWS metadata
  produced a response indicating server-side fetch.
  Evidence: Payload: http://169.254.169.254/latest/meta-data/ | HTTP 200 | Response indicates internal access
  Remediation: Validate and sanitize URL parameters. Use allowlists for permitted domains.
  OWASP: A10:2021 Server-Side Request Forgery | CWE-918
```
