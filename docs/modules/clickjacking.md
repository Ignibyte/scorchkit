# Clickjacking Detection

**Module ID:** `clickjacking` | **Category:** Scanner | **Type:** Built-in
**Source:** `src/scanner/clickjacking.rs`

## What It Does

Detects clickjacking exposure by checking whether the target page declares at
least one frame-busting defense. The module sends a single GET, reads the
response headers, and inspects both `X-Frame-Options` and the CSP
`frame-ancestors` directive. A finding is raised only when **both** defenses
are absent — having either one satisfies the check.

Only HTML responses are evaluated. If the `Content-Type` is not
`text/html` or `application/xhtml`, the module returns no findings.

## What It Checks

| Condition | Severity |
|-----------|----------|
| Page serves HTML and neither `X-Frame-Options` nor CSP `frame-ancestors` is set | Medium |

## How to Run

```
scorchkit run https://example.com --modules clickjacking
```

## Limitations

- The check is header-only — JavaScript frame-busting code (e.g.
  `if (top !== self) top.location = self.location`) is ignored.
- CSP `frame-ancestors` presence is detected by case-insensitive substring,
  not by full CSP parsing. A commented-out or malformed directive may still
  be treated as present.
- Only the response for the exact target URL is tested; inner iframes and
  sub-routes are not crawled.

## OWASP / CWE

- **A05:2021 Security Misconfiguration**, CWE-1021 (Improper Restriction of
  Rendered UI Layers).
