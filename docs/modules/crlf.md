# CRLF Injection (HTTP Response Splitting)

**Module ID:** `crlf` | **Category:** Scanner | **Type:** Built-in
**Source:** `src/scanner/crlf.rs`

## What It Does

Tests URL query parameters for HTTP response splitting / header injection by
appending CRLF sequences followed by a canary header (`X-Scorch-Injected:
true` or an injected `Set-Cookie`). The module inspects each response's
parsed headers for the canary. If the canary appears, the upstream server
took the injected bytes as literal header data — the parameter is
vulnerable.

Seven encoding variants are tested per parameter to defeat naive filters,
plus one blanket probe that appends `?scorch_test=…` when no query
parameters exist.

## What It Checks

| Payload | Technique | Severity |
|---------|-----------|----------|
| `%0d%0aX-Scorch-Injected:%20true` | Standard URL-encoded CRLF | High |
| `%250d%250aX-Scorch-Injected:%20true` | Double URL-encoded CRLF | High |
| `%E5%98%8A%E5%98%8DX-Scorch-Injected:%20true` | Unicode CRLF encoding | High |
| `%0aX-Scorch-Injected:%20true` | Bare LF (no CR) | High |
| `%0dX-Scorch-Injected:%20true` | Bare CR (no LF) | High |
| `%0d%0aSet-Cookie:%20scorch_test=injected` | Set-Cookie injection | High |
| `%0d%0a%09X-Scorch-Injected:%20true` | CRLF + tab before header | High |

For the Set-Cookie variant, detection requires the specific value
`scorch_test=injected` to appear in a response `Set-Cookie` header.

## How to Run

```
scorchkit run 'https://example.com/?redirect=/home' --modules crlf
```

The URL must contain query parameters for deep testing; an appended-parameter
probe covers parameter-less URLs with the primary payload only.

## Limitations

- `reqwest` normalizes request headers before sending — this module tests
  injection via URL encoding only, not via raw socket writes. Filters that
  reject `\r\n` but miss URL-encoded variants are exactly what's detected.
- Only query parameters are fuzzed. POST body fields, cookies, and request
  headers (other than the ones reqwest sets automatically) are not tested.
- Response inspection is limited to parsed headers; CRLF that ends up in the
  response *body* without affecting headers is not flagged.
- Stops at the first matching payload per parameter to limit request volume.

## OWASP / CWE

- **A03:2021 Injection**, CWE-113 (Improper Neutralization of CRLF Sequences
  in HTTP Headers).
