# CNAME Takeover & Certificate Transparency

**Module ID:** `cname_takeover` | **Category:** Recon | **Type:** Built-in
**Source:** `src/recon/cname_takeover.rs`

## What It Does

Detects dangling CNAME records pointing to deprovisioned third-party services
and enumerates subdomains via certificate transparency logs. The module
fetches the target URL and searches the response body for 16 well-known
service-error fingerprints (GitHub Pages, Heroku, AWS S3, Shopify, Fastly,
Fly.io, Tumblr, Surge.sh, etc.). It also queries `crt.sh` for every
subdomain issued under the target apex, which often reveals forgotten
staging and legacy hosts worth testing for takeover.

## What It Checks

- **Service takeover fingerprint** (High) — response body contains any of 16
  error signatures such as "There isn't a GitHub Pages site here",
  "NoSuchBucket", "Domain is not configured" (Fastly), "Sorry, this shop is
  currently unavailable" (Shopify). Indicates the CNAME target is claimable.
- **Certificate transparency enumeration** (Info) — `crt.sh` query returned
  subdomains for the target apex. Emits one aggregated finding listing the
  first 20 subdomains as a lead for further testing.

## How to Run

```
scorchkit run https://example.com --modules cname_takeover
```

## Limitations

- `crt.sh` is queried without an API key and is rate-limited; large apexes
  may return incomplete data or time out.
- The fingerprint list is English-only and focused on US-centric SaaS
  providers. Internationalized error pages and niche hosts (Cargo, Readme.io,
  Unbounce) are not covered.
- This module probes the *target URL* for takeover fingerprints, not each
  subdomain returned by `crt.sh`. Use the subdomain list as a manual lead.
- Wildcard entries from `crt.sh` are explicitly filtered out.

## OWASP / CWE

- **A05:2021 Security Misconfiguration**, CWE-923 (Improper Restriction of
  Communication Channel to Intended Endpoints) for takeover; CWE-200 for
  transparency enumeration.
