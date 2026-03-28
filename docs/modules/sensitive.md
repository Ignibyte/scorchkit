# Sensitive Data Exposure

**Module ID:** `sensitive` | **Category:** Scanner | **Type:** Built-in
**Source:** `src/scanner/sensitive.rs`

## What It Does

Scans HTTP response bodies for exposed secrets, API keys, cryptographic material, and source maps. It combines substring pattern matching for 16 known secret formats with heuristic detection for generic API key patterns, and probes for publicly accessible JavaScript source map files.

## Checks Performed

### Secret Patterns (16)

| Pattern | Name | Severity |
|---------|------|----------|
| `AKIA` | AWS Access Key ID | Critical |
| `-----BEGIN RSA PRIVATE KEY-----` | RSA Private Key | Critical |
| `-----BEGIN PRIVATE KEY-----` | Private Key | Critical |
| `-----BEGIN EC PRIVATE KEY-----` | EC Private Key | Critical |
| `sk_live_` | Stripe Secret Key | Critical |
| `sk_test_` | Stripe Test Key | Medium |
| `ghp_` | GitHub Personal Access Token | High |
| `gho_` | GitHub OAuth Token | High |
| `glpat-` | GitLab Personal Access Token | High |
| `xoxb-` | Slack Bot Token | High |
| `xoxp-` | Slack User Token | High |
| `SG.` | SendGrid API Key | High |
| `sq0csp-` | Square Access Token | High |
| `AIza` | Google API Key | Medium |
| `eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9` | Hardcoded JWT | Medium |
| `password` | Password Reference | Info |

### False Positive Reduction

Matches are suppressed if the surrounding 80-character context contains any of: `example`, `placeholder`, `xxx`, `your_`, `insert`, `todo`.

### API Key Heuristics (7)

Generic key/value patterns are detected for: `api_key`, `apikey`, `api-key`, `secret_key`, `private_key`, `access_token`, `client_secret`

The module looks for these in JSON (`"api_key":`) and query string (`api_key=`) formats. Values must be at least 16 characters long and not contain placeholder words.

### Source Map Detection

| Check | Description |
|-------|-------------|
| `sourceMappingURL=` in response | Reference to source map found inline |
| `/main.js.map` | Common source map file |
| `/app.js.map` | Common source map file |
| `/bundle.js.map` | Common source map file |

Source map files are confirmed by checking for `"sources"` and `"mappings"` keys in the response.

## Findings

| Finding | Severity | CWE | Trigger |
|---------|----------|-----|---------|
| Exposed AWS Access Key ID | Critical | 200 | `AKIA` found in response |
| Exposed RSA/EC/Private Key | Critical | 200 | PEM header found in response |
| Exposed Stripe Secret Key | Critical | 200 | `sk_live_` found in response |
| Exposed GitHub/GitLab/Slack/SendGrid/Square Token | High | 200 | Token prefix found in response |
| Possible API Key/Secret in Response | High | 200 | Heuristic key=value pattern with real-looking value |
| Source Map Reference Found | Low | 540 | `sourceMappingURL=` in response body |
| Source Map Exposed | Medium | 540 | `.js.map` file returns 200 with valid source map content |

## OWASP Coverage

**A02:2021 -- Cryptographic Failures.** Covers exposure of secrets and API keys in client-facing responses.

**A05:2021 -- Security Misconfiguration.** Covers source map exposure in production builds.

## How It Works

1. A GET request fetches the target page body.
2. **Pattern matching:** The body is scanned for each of the 16 secret patterns via `str::contains`. When a match is found, the surrounding context is checked for placeholder indicators to reduce false positives.
3. **Heuristic matching:** For each of the 7 API key indicators, the module searches for `"indicator"`, `indicator=`, and `indicator:` patterns. The value after the delimiter is extracted, and if it is 16+ alphanumeric characters without placeholder words, a finding is emitted.
4. **Source map inline check:** The response body is checked for `sourceMappingURL=`.
5. **Source map file probe:** Three common source map paths are requested. If any returns HTTP 200 with JSON containing `"sources"` and `"mappings"`, the source map is confirmed as exposed.

## Example Output

```
[Critical] Exposed AWS Access Key ID
  AWS Access Key ID pattern found in response body. This may expose credentials or API access.
  Evidence: ...config: AKIAxxxxxxxxxxxxxxxx...
  Remediation: Remove AWS Access Key ID from client-facing responses. Use environment variables server-side.
  OWASP: A02:2021 Cryptographic Failures | CWE-200
```
