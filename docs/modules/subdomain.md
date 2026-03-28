# Subdomain Enumeration

**Module ID:** `subdomain` | **Category:** Recon | **Type:** Built-in
**Source:** `src/recon/subdomain.rs`

## What It Does

Enumerates subdomains of the target domain by performing DNS brute-force resolution against a curated 57-word wordlist. For each discovered subdomain, the module resolves IP addresses and flags subdomains that match patterns associated with sensitive or internal infrastructure. This helps identify the target's attack surface beyond the primary domain.

## Checks Performed

### DNS Brute-Force Wordlist (57 words)

The module attempts to resolve each prefix as `{prefix}.{target_domain}` using tokio's async DNS resolver:

```
www, mail, remote, blog, webmail, server, ns1, ns2,
smtp, secure, vpn, m, shop, ftp, mail2, test,
portal, ns, host, support, dev, web,
mx, email, cloud, admin, api, stage, staging,
app, git, gitlab, jenkins, ci, jira, confluence,
wiki, docs, status, monitor, grafana, kibana,
db, cdn, media, static, assets, images,
internal, intranet, corp, uat, qa, sandbox,
demo, beta, old, legacy, backup,
sso, auth, login, id, oauth
```

### Interesting Subdomain Patterns (18 rules)

Discovered subdomains are matched against 18 patterns that indicate potentially sensitive infrastructure:

| Pattern | Description | Severity |
|---------|-------------|----------|
| `admin` | Administrative panel subdomain | Medium |
| `staging` | Staging environment exposed | Medium |
| `stage` | Staging environment exposed | Medium |
| `dev` | Development environment exposed | Medium |
| `test` | Test environment exposed | Medium |
| `uat` | UAT environment exposed | Medium |
| `internal` | Internal subdomain publicly resolvable | High |
| `intranet` | Intranet subdomain publicly resolvable | High |
| `jenkins` | CI/CD tool subdomain found | Medium |
| `gitlab` | Source code platform subdomain | Medium |
| `git` | Git server subdomain | Medium |
| `jira` | Project management tool exposed | Low |
| `grafana` | Monitoring dashboard exposed | Medium |
| `kibana` | Log analysis dashboard exposed | Medium |
| `db` | Database subdomain found | High |
| `backup` | Backup system subdomain | Medium |
| `vpn` | VPN endpoint found | Info |
| `sso` | SSO endpoint found | Info |

## Findings

| Title | Severity | Description |
|-------|----------|-------------|
| {N} Subdomains Discovered | Info | Summary of all discovered subdomains with resolved IPs |
| Interesting Subdomain: {subdomain} | Varies | Subdomain matches a sensitive infrastructure pattern |

## OWASP Coverage

- **A05:2021 -- Security Misconfiguration**: Staging, development, and test environments exposed to the public internet
- **A01:2021 -- Broken Access Control**: Internal/intranet subdomains publicly resolvable, admin panels on subdomains

## How It Works

1. Extracts the target domain from the scan context. Fails with an error if no domain is available (e.g., when scanning an IP address).
2. Iterates through the 57-word subdomain wordlist.
3. For each candidate, performs async DNS resolution via `tokio::net::lookup_host` on `{prefix}.{domain}:80`.
4. Successful resolutions (NOERROR with addresses) are collected with their deduplicated IP addresses.
5. If any subdomains are discovered:
   - A summary finding lists all discovered subdomains and their resolved IPs.
   - Each discovered subdomain is checked against 18 "interesting" patterns using case-insensitive prefix matching.
   - Matching subdomains generate additional findings with severity levels based on the type of infrastructure identified (High for internal/db, Medium for dev/staging/CI tools, Low/Info for project management and VPN).

## Example Output

```
[INFO] 5 Subdomains Discovered
  URL: https://example.com/
  Subdomain enumeration found 5 active subdomain(s) for example.com.
  Evidence: Discovered subdomains:
    www.example.com -> 93.184.216.34
    mail.example.com -> 93.184.216.35
    staging.example.com -> 10.0.1.50
    admin.example.com -> 93.184.216.34
    dev.example.com -> 10.0.1.51

[MEDIUM] Interesting Subdomain: staging.example.com
  URL: https://example.com/
  Staging environment exposed: staging.example.com -> 10.0.1.50
  Evidence: staging.example.com -> 10.0.1.50

[MEDIUM] Interesting Subdomain: admin.example.com
  URL: https://example.com/
  Administrative panel subdomain: admin.example.com -> 93.184.216.34
  Evidence: admin.example.com -> 93.184.216.34

[MEDIUM] Interesting Subdomain: dev.example.com
  URL: https://example.com/
  Development environment exposed: dev.example.com -> 10.0.1.51
  Evidence: dev.example.com -> 10.0.1.51
```
