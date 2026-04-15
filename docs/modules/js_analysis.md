# JavaScript File Analysis

**Module ID:** `js_analysis` | **Category:** Recon | **Type:** Built-in
**Source:** `src/recon/js_analysis.rs`

## What It Does

Parses the target HTML for `<script src="...">` references, fetches each
referenced JavaScript file (capped at 30), and scans both inline and external
JavaScript bodies for embedded secrets, API endpoint patterns, and source
map references. This is string-pattern matching — it does not execute JS and
does not walk the full module graph.

## What It Checks

| Class | Trigger | Severity |
|-------|---------|----------|
| AWS Access Key ID (`AKIA…`) | Pattern literal in JS | Critical |
| AWS Temporary Access Key (`ASIA…`) | Pattern literal in JS | Critical |
| Stripe live key (`sk_live_`) | Pattern literal | Critical |
| Stripe test key (`sk_test_`) | Pattern literal | High |
| GitHub PAT / OAuth (`ghp_`, `gho_`) | Pattern literal | Critical |
| GitLab PAT (`glpat-`) | Pattern literal | Critical |
| Slack tokens (`xoxb-`, `xoxp-`) | Pattern literal | Critical |
| Google API key (`AIzaSy…`) | Pattern literal | High |
| Bearer token, OAuth `client_secret`, `api_secret` | Literal | High |
| RSA / PKCS8 private key PEM header | Literal | Critical |
| `api_key` reference | Literal | Medium |
| API endpoints (`/api/`, `/v1/`, `/graphql`, `/admin/`, `/debug/`, `/swagger`, `/_debug`, `/_admin`) | Literal | Info |
| Source map reference (`//# sourceMappingURL=`) | Literal in external JS | Medium |

## How to Run

```
scorchkit run https://example.com --modules js_analysis
```

## Limitations

- No entropy analysis — short or format-compliant high-entropy secrets that
  do not match a known prefix (e.g. generic 32-char hex tokens) are missed.
  For deeper secret hunting, pair with the `trufflehog` tool wrapper.
- Only `<script src=…>` tags are followed. Dynamically injected scripts,
  web worker sources, and inline-imported ES modules are not traversed.
- External JS is capped at 30 files and processed sequentially.
- API endpoint detection is a literal substring match; false positives on
  prose mentions of `/api/` are possible.

## OWASP / CWE

- Secrets: **A01:2021 Broken Access Control**, CWE-540 (Inclusion of
  Sensitive Information in Source Code).
- Source maps: **A05:2021 Security Misconfiguration**, CWE-540.
- Endpoint disclosure: **A01:2021 Broken Access Control**, CWE-615.
