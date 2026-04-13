# TLS/SSL Analysis

**Module ID:** `ssl` | **Category:** Scanner | **Type:** Built-in
**Source:** `src/scanner/ssl.rs`

## What It Does

Analyzes the target's TLS/SSL certificate and connection configuration. It performs a full TLS handshake, extracts the leaf certificate using DER parsing, and checks for expiration, trust chain issues, weak cryptography, and hostname mismatches. If the target is served over plain HTTP, it flags the absence of encryption entirely.

## Checks Performed

| Check | Description |
|-------|-------------|
| No TLS encryption | Target is served over plain HTTP |
| TLS connection failure | Handshake cannot be completed |
| Certificate expiration | Cert is expired or expires within 30 days |
| Self-signed certificate | Subject and issuer are identical |
| Weak signature algorithm | SHA-1 with RSA or MD5 with RSA |
| Subject/SAN mismatch | Domain does not match CN or any SAN entry |
| Wildcard matching | Validates `*.example.com` against single-level subdomains |

## Findings

| Finding | Severity | CWE | Trigger |
|---------|----------|-----|---------|
| No TLS/SSL Encryption | High | 319 | Target URL uses `http://` scheme |
| TLS Connection Failed | High | -- | TCP connect or TLS handshake error |
| TLS Certificate Expired | Critical | 295 | `not_after` date is in the past |
| TLS Certificate Expiring Soon | Medium | -- | Fewer than 30 days until expiration |
| Self-Signed TLS Certificate | High | 295 | `subject == issuer` in the parsed cert |
| Weak Certificate Signature Algorithm | High | 328 | OID maps to SHA-1/RSA or MD5/RSA |
| Certificate Subject Mismatch | High | 295 | Domain not in CN and not in any SAN DNS entry |

## OWASP Coverage

**A02:2021 -- Cryptographic Failures.** Covers missing encryption, expired or untrusted certificates, and use of deprecated signature algorithms that enable collision attacks.

## How It Works

1. If the target scheme is not HTTPS, a finding is emitted immediately and no connection is attempted.
2. A TCP connection is opened to `domain:port`, then a TLS handshake is performed using `tokio-rustls` with the Mozilla root certificate store (`webpki-roots`).
3. The leaf certificate DER bytes are extracted from the peer certificate chain via `peer_certificates()`.
4. `x509-parser` decodes the DER into structured fields: subject CN, issuer CN, SAN extension, validity timestamps, and the signature algorithm OID.
5. The signature algorithm OID is mapped to a human-readable name; OIDs for SHA-1/RSA (`1.2.840.113549.1.1.5`) and MD5/RSA (`1.2.840.113549.1.1.4`) are tagged as `WEAK`.
6. Expiration is computed via `chrono::Utc::now()` against the certificate's `not_after` timestamp.
7. Wildcard matching strips the `*.` prefix and verifies the domain ends with the suffix and has exactly one additional subdomain level.

## Example Output

```
[Critical] TLS Certificate Expired
  The TLS certificate expired. Not After: Mon, 15 Jan 2024 00:00:00 GMT
  Evidence: Subject: example.com | Issuer: Let's Encrypt | Expired: Mon, 15 Jan 2024 00:00:00 GMT
  Remediation: Renew the TLS certificate immediately
  OWASP: A02:2021 Cryptographic Failures | CWE-295
```
