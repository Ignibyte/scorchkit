# Host Header Injection

**Module ID:** `host_header` | **Category:** Scanner | **Type:** Built-in
**Source:** `src/scanner/host_header.rs`

## What It Does

Detects host header injection vulnerabilities by sending requests with
`X-Forwarded-Host` and related override headers set to a canary value
(`scorch-evil-host.example.com`), then checking whether the server reflects
that value in the response body. Reflection into a URL attribute
(`href`, `src`, `action`, `content`) is treated as cache-poisoning-grade
and flagged Critical.

## What It Checks

- **Baseline reflection** (High) — any of five override headers
  (`X-Forwarded-Host`, `X-Host`, `X-Forwarded-Server`, `X-Original-URL`,
  `X-Rewrite-URL`) causes the canary to appear in the response body.
- **Cache-poisoning reflection** (Critical) — `X-Forwarded-Host` plus
  `X-Forwarded-Proto: https` causes the canary to appear inside a URL
  attribute matching one of:
  `href="https?://…`, `src="https?://…`, `action="https?://…`,
  `content="https?://…`. This is the direct cache-poisoning / password-reset
  poisoning vector.

A baseline request is taken first. If the canary already appears naturally
in the response (it won't, under normal conditions), the module aborts to
avoid false positives.

## How to Run

```
scorchkit run https://example.com --modules host_header
```

## Limitations

- The canary-reflection check is case-sensitive substring match on the full
  response body — reflections that rewrite or HTML-escape the canary may be
  missed.
- Only one finding per override header is emitted.
- Cache-poisoning detection requires the attacker-controlled host to appear
  in a *URL attribute*. Reflection in text content only (rare) is caught by
  the baseline check but not escalated to Critical.
- The module does not attempt to *confirm* cache poisoning by issuing a
  follow-up uncached request.

## OWASP / CWE

- Baseline reflection: **A03:2021 Injection**, CWE-644 (Improper
  Neutralization of HTTP Headers for Scripting Syntax).
- Cache poisoning: **A05:2021 Security Misconfiguration**, CWE-644.
