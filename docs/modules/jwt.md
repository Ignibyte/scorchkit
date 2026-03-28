# JWT Analysis

**Module ID:** `jwt` | **Category:** Scanner | **Type:** Built-in
**Source:** `src/scanner/jwt.rs`

## What It Does

Finds JWT tokens in HTTP response cookies, headers, and the response body, then analyzes each token for cryptographic weaknesses and insecure configuration. It decodes the header and payload (base64url) without requiring the signing key, checking for dangerous algorithms, missing signatures, sensitive data exposure, and expiration issues.

## Checks Performed

### Token Discovery

| Source | Method |
|--------|--------|
| Cookies | Scans all `Set-Cookie` headers for JWT-shaped values (three dot-separated base64url segments) |
| Authorization header | Checks for `Bearer <jwt>` in the response `Authorization` header |
| Response body | Scans for `eyJ`-prefixed tokens in whitespace-delimited words and JSON string values (up to 5 tokens) |

### Security Analysis

| Check | Description |
|-------|-------------|
| `alg: none` | Token has no signature verification -- can be freely forged |
| Empty signature | Third JWT segment is empty |
| Symmetric algorithm | HS256, HS384, or HS512 -- vulnerable if secret is weak/leaked |
| Sensitive claims | Payload contains keys matching: `password`, `pwd`, `secret`, `ssn`, `credit_card`, `cc`, `api_key`, `apikey`, `private_key` |
| Missing expiration | No `exp` claim -- token never expires |
| Long expiration | `exp` claim is more than 30 days in the future |

## Findings

| Finding | Severity | CWE | Trigger |
|---------|----------|-----|---------|
| JWT Using 'none' Algorithm | Critical | 327 | Header `alg` field is `none` (case-insensitive) |
| JWT Has Empty Signature | High | 345 | Third dot-separated segment is empty |
| Sensitive Data in JWT Payload | High | 312 | Payload contains sensitive-looking claim key |
| JWT Missing Expiration Claim | Medium | 613 | No `exp` field in payload |
| JWT Has Long Expiration | Low | -- | `exp` is more than 30 days from now |
| JWT Using Symmetric Algorithm | Info | -- | `alg` is HS256, HS384, or HS512 |

## OWASP Coverage

**A02:2021 -- Cryptographic Failures.** Covers the `alg:none` bypass, weak symmetric signing, and exposure of sensitive data in unencrypted JWT payloads.

**A07:2021 -- Identification and Authentication Failures.** Covers missing or excessive token expiration that extends the attack window for stolen tokens.

## How It Works

1. A GET request is made to the target URL. Both the response headers and body are captured.
2. **Cookie extraction:** All `Set-Cookie` headers are split on `=` and `;` to isolate cookie values. Each value is checked by `is_jwt` (three non-empty base64url segments separated by dots).
3. **Body extraction:** The body is scanned for `eyJ`-prefixed strings (base64url encoding of `{"` which starts all JWT headers). Candidates are extracted from whitespace-delimited tokens and JSON string values, deduplicated, and capped at 5.
4. **Header decoding:** The first JWT segment is base64url-decoded (with automatic padding) and parsed as JSON. The `alg` field is inspected.
5. **Payload decoding:** The second segment is decoded and parsed. Claim keys are checked against the sensitive-key list. The `exp` claim is compared to the current UTC timestamp.
6. **Signature check:** The third segment is checked for emptiness.

## Example Output

```
[Critical] JWT Using 'none' Algorithm
  A JWT from cookie:session uses the 'none' algorithm. This means the token
  has no signature verification and can be freely forged by anyone.
  Evidence: Source: cookie:session | Algorithm: none
  Remediation: Never allow the 'none' algorithm. Enforce HS256, RS256, or ES256.
  OWASP: A02:2021 Cryptographic Failures | CWE-327
```
