# DNS & Email Security

**Module ID:** `dns-security` | **Category:** Recon | **Type:** Built-in
**Source:** `src/recon/dns.rs`

## What It Does

Queries DNS records via DNS-over-HTTPS (Cloudflare JSON API) to assess email authentication and DNS security posture. The module checks SPF record permissiveness, DMARC policy enforcement, and MX record presence. No DNS crate is required -- it uses the existing `reqwest` HTTP client to query Cloudflare's DoH endpoint (`https://cloudflare-dns.com/dns-query`) with `Accept: application/dns-json`.

## Checks Performed

| # | Record Type | Check | Condition |
|---|-------------|-------|-----------|
| 1 | TXT (SPF) | Missing SPF | No `v=spf1` TXT record found for the domain |
| 2 | TXT (SPF) | Permissive SPF (+all) | SPF mechanism is `+all` (pass all senders) |
| 3 | TXT (SPF) | Permissive SPF (?all) | SPF mechanism is `?all` (neutral, no enforcement) |
| 4 | TXT (SPF) | Weak SPF (~all) | SPF mechanism is `~all` (soft fail, not rejected) |
| 5 | TXT (DMARC) | Missing DMARC | No `v=DMARC1` TXT record at `_dmarc.<domain>` |
| 6 | TXT (DMARC) | DMARC policy none | DMARC `p=none` (monitoring only, no enforcement) |
| 7 | MX | MX records present | Informational -- lists mail servers for the domain |

## Findings

| Title | Severity | Description |
|-------|----------|-------------|
| No SPF Record: \<domain\> | Medium | No SPF record found; any server can send email as this domain |
| Permissive SPF Record: \<domain\> (+all) | High | SPF uses +all, allowing any server to pass SPF checks |
| Permissive SPF Record: \<domain\> (?all) | Medium | SPF uses ?all (neutral), providing no enforcement |
| Permissive SPF Record: \<domain\> (~all) | Low | SPF uses ~all (soft fail), marking but not rejecting unauthorized senders |
| No DMARC Record: \<domain\> | Medium | No DMARC policy for handling emails that fail SPF/DKIM authentication |
| DMARC Policy Set to None: \<domain\> | Medium | DMARC policy is p=none (monitoring only), providing no protection |
| MX Records Found: \<domain\> | Info | Informational listing of mail servers |

## OWASP Coverage

- **A05:2021 -- Security Misconfiguration**: All checks map to this category, covering missing or weak email authentication configuration.

### CWE References

| CWE | Name | Applies To |
|-----|------|------------|
| CWE-290 | Authentication Bypass by Spoofing | Missing/weak SPF, missing/weak DMARC |

## How It Works

1. Extracts the domain from the target URL. Skips silently if no domain is available.
2. Queries Cloudflare's DNS-over-HTTPS JSON API (`application/dns-json`) for TXT records on the target domain.
3. Searches TXT records for an SPF record (`v=spf1`) and analyzes the trailing mechanism (`-all`, `~all`, `?all`, `+all`).
4. Queries TXT records on `_dmarc.<domain>` for a DMARC record (`v=DMARC1`) and extracts the `p=` policy value.
5. Queries MX records to identify mail servers.
6. All findings include remediation guidance and OWASP/CWE references.

## Implementation Details

- **No DNS crate**: Uses the shared `reqwest` HTTP client from `ScanContext` to perform DoH queries, avoiding an additional dependency.
- **DoH JSON format**: Cloudflare returns `{ "Answer": [{ "data": "..." }, ...] }`. The module parses this with `serde_json`.
- **Domain extraction**: Uses `ctx.target.domain` which is parsed from the target URL during target creation.

## Example Output

```
[MEDIUM] No SPF Record: example.com
  URL: https://example.com/
  No SPF record found for 'example.com'. Without SPF, any server can
  send emails claiming to be from this domain.
  Evidence: No v=spf1 TXT record for example.com
  Remediation: Add an SPF record: example.com TXT "v=spf1 include:_spf.google.com -all"
  OWASP: A05:2021 Security Misconfiguration
  CWE: 290

[MEDIUM] No DMARC Record: example.com
  URL: https://example.com/
  No DMARC record found for 'example.com'. Without DMARC, the domain has
  no policy for handling emails that fail SPF/DKIM authentication.
  Evidence: No TXT record at _dmarc.example.com
  Remediation: Add a DMARC record: _dmarc.example.com TXT "v=DMARC1; p=reject; rua=mailto:dmarc@example.com"
  OWASP: A05:2021 Security Misconfiguration
  CWE: 290

[INFO] MX Records Found: example.com
  URL: https://example.com/
  Domain 'example.com' has 2 MX record(s): 10 mail.example.com, 20 backup.example.com.
  Evidence: 2 MX records
  OWASP: A05:2021 Security Misconfiguration
```
