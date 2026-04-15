# Virtual Host Discovery

**Module ID:** `vhost` | **Category:** Recon | **Type:** Built-in
**Source:** `src/recon/vhost.rs`

## What It Does

Brute-forces the HTTP `Host` header against the target IP to surface hidden
virtual hosts — internal portals, staging environments, admin panels — that
share the same front-end server but are not linked from the public site.
The module first records a baseline response (using an invalid host) and
then compares each candidate against that baseline on status code and body
size.

## What It Checks

- **Virtual host discovery** (Info) — for each prefix in the wordlist, the
  request `GET {url}` with `Host: {prefix}.{domain}` is sent. A vhost is
  considered unique when either the HTTP status differs from baseline, or
  the response body differs by more than 25 % of the baseline size, and the
  status is < 500. Produces one aggregated finding listing every discovered
  vhost with its status and body length.

The default wordlist includes 34 common prefixes (`admin`, `api`, `staging`,
`dev`, `internal`, `jenkins`, `grafana`, `vpn`, `portal`, `webmail`, etc.).
A custom wordlist can be provided via `wordlists.vhost` in `config.toml`.

## How to Run

```
scorchkit run https://example.com --modules vhost
```

Custom wordlist:

```toml
# config.toml
[wordlists]
vhost = "/path/to/vhost-prefixes.txt"
```

## Limitations

- The module relies on application-layer `Host` header routing; CDNs that
  require SNI-matching (Cloudflare, Fastly) commonly strip non-matching
  hosts and yield no discovery signal.
- Body-size diffing is lossy — dynamic pages (timestamps, CSRF tokens) can
  produce false positives. The 25 % threshold is a rough heuristic.
- No status-code filtering on success: any < 500 response that differs from
  baseline is reported, including soft 404s.
- Virtual hosts served only over HTTPS with strict SNI are not reachable
  when the target URL is HTTP, and vice versa.

## OWASP / CWE

- **A05:2021 Security Misconfiguration**, CWE-200 (Exposure of Sensitive
  Information).
