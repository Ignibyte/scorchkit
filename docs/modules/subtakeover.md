# Subdomain Takeover

**Module ID:** `subtakeover` | **Category:** Scanner | **Type:** Built-in
**Source:** `src/scanner/subtakeover.rs`

## What It Does

Detects subdomain takeover vulnerabilities by probing common subdomains of the target domain and matching HTTP response bodies against known cloud provider "unclaimed resource" fingerprints. A match indicates the subdomain's DNS record (typically a CNAME) points to a service that can be claimed by an attacker, allowing them to serve arbitrary content on your domain.

## Checks Performed

| Check | Description |
|-------|-------------|
| Subdomain probing | Generates 15 common subdomains (www, mail, admin, staging, dev, api, cdn, etc.) |
| Cloud provider fingerprinting | Matches response bodies against 8 provider-specific error page patterns |
| Dual scheme testing | Tries both HTTPS and HTTP for each subdomain |

## Provider Fingerprints

| Provider | Fingerprint Pattern | Default Severity |
|----------|-------------------|-----------------|
| GitHub Pages | "There isn't a GitHub Pages site here" | High |
| Heroku | "No such app" / "herokucdn.com/error-pages" | High |
| AWS S3 | "NoSuchBucket" / "The specified bucket does not exist" | Critical |
| Azure | "404 Web Site not found" | High |
| Shopify | "Sorry, this shop is currently unavailable" | Medium |
| Fastly | "Fastly error: unknown domain" | High |
| Pantheon | "404 error unknown site" | Medium |
| Tumblr | "There's nothing here" | Medium |

## Findings

| Finding | Severity | CWE | Trigger |
|---------|----------|-----|---------|
| Subdomain Takeover: {subdomain} ({provider}) | Varies by provider | 200 | Response body matches a cloud provider's unclaimed resource fingerprint |

## OWASP Coverage

**A05:2021 -- Security Misconfiguration.** Covers dangling DNS records pointing to deprovisioned cloud resources that can be claimed by attackers for phishing, cookie theft, and reputation damage.

## How It Works

1. **Subdomain generation**: Prepends 15 common prefixes (`www`, `mail`, `admin`, `staging`, `dev`, `api`, `cdn`, `assets`, `blog`, `docs`, `app`, `test`, `beta`, `old`, `new`) to the target domain.
2. **HTTP probing**: For each subdomain, tries HTTPS first, then HTTP. Fetches the response body.
3. **Fingerprint matching**: Checks the response body against 8 cloud provider fingerprint patterns. Each fingerprint has one or more body strings and an assigned severity level.
4. **Finding emission**: When a fingerprint matches, emits a finding with the provider name, subdomain, and severity based on the provider's risk level (AWS S3 is Critical due to bucket claim risk; Shopify/Pantheon/Tumblr are Medium).

## Example Output

```
[Critical] Subdomain Takeover: staging.example.com (AWS S3)
  The subdomain 'staging.example.com' appears to point to an unclaimed AWS S3
  resource. An attacker can claim this resource and serve arbitrary content on
  your domain, enabling phishing, cookie theft, and reputation damage.
  Evidence: Provider: AWS S3 | Fingerprint matched in response body
  Remediation: Remove the dangling DNS record or reclaim the resource
  OWASP: A05:2021 Security Misconfiguration | CWE-200
```
