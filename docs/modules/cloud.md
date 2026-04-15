# Cloud Metadata & Bucket Enumeration

**Module ID:** `cloud` | **Category:** Recon | **Type:** Built-in
**Source:** `src/recon/cloud.rs`

## What It Does

Identifies the cloud provider hosting the target and enumerates candidate
storage buckets derived from the target domain. The module inspects response
headers for provider-specific indicator headers (AWS, GCP, Azure, Cloudflare,
Vercel, Netlify, Fly.io, DigitalOcean) and then brute-forces a list of common
S3 bucket-name suffixes against `{base}.s3.amazonaws.com`. Buckets that return
HTTP 200 (publicly listable) or HTTP 403 (exists but access-controlled) are
reported.

## What It Checks

- **Cloud provider detection** (Info) — any of 17 indicator headers present:
  `x-amz-request-id`, `x-amz-cf-id`, `x-goog-*`, `x-ms-request-id`,
  `x-azure-ref`, `cf-ray`, `x-vercel-id`, `x-netlify-request-id`,
  `fly-request-id`, etc. Emits one finding summarizing all detected providers.
- **Public S3 bucket discovery** (High) — for each of 19 bucket-name suffixes
  (`-assets`, `-backup`, `-dev`, `-prod`, `-staging`, `-uploads`, etc.) the
  derived base hostname is probed at `https://{base}{suffix}.s3.amazonaws.com/`.
  Severity is High when at least one bucket responds HTTP 200 (public listing),
  Medium when every discovered bucket is 403-only.

## How to Run

```
scorchkit run https://example.com --modules cloud
```

## Limitations

- Bucket enumeration only covers AWS S3 in the path-style
  `{name}.s3.amazonaws.com` URL. GCS and Azure Blob Storage are not probed.
- The base name is derived from the first DNS label (`example.com` →
  `example`). Deeply nested subdomains or non-obvious bucket-naming schemes
  are not discovered.
- Cloud-provider detection relies on response headers only — stripped or
  proxied headers produce false negatives.
- AWS IMDS (`169.254.169.254`) is not probed from the scanner host; this
  module surfaces cloud *indicators*, not active metadata-endpoint SSRF.

## OWASP / CWE

- Provider detection: **A05:2021 Security Misconfiguration**, CWE-200.
- Bucket exposure: **A01:2021 Broken Access Control**, CWE-284.
