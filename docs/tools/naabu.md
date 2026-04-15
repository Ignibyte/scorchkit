# naabu

ProjectDiscovery's port scanner — a single Go binary that pairs naturally with the rest of the ProjectDiscovery suite (`httpx`, `katana`, `nuclei`). License: MIT (upstream: [projectdiscovery/naabu](https://github.com/projectdiscovery/naabu)).

## Install

```
go install github.com/projectdiscovery/naabu/v2/cmd/naabu@latest
```

Verify with `scorchkit doctor`.

## What ScorchKit surfaces

The wrapper invokes `naabu -host <host> -top-ports 1000 -silent -json`, parses each JSON-Lines record for `port`, and consolidates into a single **Info** finding:

- **Title**: `naabu: N TCP port(s) open on <host>`
- **Evidence**: first 20 ports (`Open ports: 22, 80, 443, ...`)
- **OWASP**: A05:2021 Security Misconfiguration
- **Confidence**: 0.9

## How to run

```
scorchkit run https://target.example.com --modules naabu
```

180s timeout. Top-1000 sweep by default.

## Limitations vs alternatives

- **vs `masscan`**: naabu is the simpler and more portable choice (no root, standalone binary). Prefer it for targeted scans. Reach for masscan when you need to sweep a /16 or larger at high pps.
- **vs `nmap`**: naabu is a port-discovery tool only — no service version detection, no OS fingerprinting, no NSE scripts. Use nmap's output as input into `cve_match`; use naabu upstream when all you need is the open-port list.
- Enrich findings by pipelining to `nmap` (service/version) or `httpx` (HTTP fingerprint).
