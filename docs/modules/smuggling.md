# HTTP Request Smuggling Detection

**Module ID:** `smuggling` | **Category:** Scanner | **Type:** Built-in
**Source:** `src/scanner/smuggling.rs`

## What It Does

Screens for request-smuggling risk heuristically. Because `reqwest`
normalizes HTTP headers and does not let us send raw CL.TE / TE.CL desync
payloads, this module instead (1) detects a multi-tier proxy architecture
from response headers, (2) probes `Transfer-Encoding` obfuscation variants
and compares response-status consistency, and (3) tests whether the backend
honors `Content-Length: 0` when the body is non-empty.

For confirmed exploitation, follow up with purpose-built tools (`smuggler.py`,
Burp's HTTP Request Smuggler extension).

## What It Checks

**Proxy indicator headers** (17): `via`, `x-forwarded-*`, `x-real-ip`,
`x-cache*`, `x-served-by`, `x-timer`, `cf-ray`, `x-amz-cf-id`,
`x-azure-ref`, `x-varnish`, `x-cdn`, `x-edge-ip`, `x-akamai-transformed`,
`fastly-io-info`.

**TE obfuscation variants** (9): `chunked`, ` chunked`, `chunked `,
`\tchunked`, `Chunked`, `CHUNKED`, `chunked\r\nTransfer-Encoding: x`
(double-TE), `xchunked`, `x]chunked`.

| Condition | Severity |
|-----------|----------|
| Proxy architecture detected AND different TE variants produce different status codes | High |
| Proxy architecture detected AND `Content-Length: 0` with a body returns the same status as correct CL | Medium |
| `Connection: close` response with proxy indicators present | Info |

## How to Run

```
scorchkit run https://example.com --modules smuggling
```

The TE-obfuscation and CL-handling probes only run when at least one proxy
indicator is detected — behind a direct server, only the header-level
check applies.

## Limitations

- Heuristic, not exploitation. The findings flag *prerequisites* for
  request smuggling (multi-tier architecture, inconsistent TE parsing);
  confirm with a real desync tool.
- Confidence is 0.5 across findings.
- `reqwest` may rewrite or reject certain `Transfer-Encoding` values before
  they hit the wire, so some obfuscation variants test header-parsing
  differences rather than pure raw-byte smuggling.
- HTTP/2 targets are not specifically handled — the probe assumes HTTP/1.1
  semantics.

## OWASP / CWE

- **A05:2021 Security Misconfiguration**, CWE-444 (Inconsistent
  Interpretation of HTTP Requests / "HTTP Request Smuggling").
