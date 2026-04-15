# masscan

High-speed TCP port scanner, orders of magnitude faster than nmap on large CIDR ranges. License: AGPL-3.0 (upstream: [robertdavidgraham/masscan](https://github.com/robertdavidgraham/masscan)).

## Install

```
apt install masscan    # Debian / Ubuntu
```

Or build from source per upstream. Verify with `scorchkit doctor`.

## What ScorchKit surfaces

The wrapper invokes `masscan <host> -p0-1023 --rate 1000 -oG -` (greppable output), parses every `Host: ... Ports: <n>/open/tcp/...` line, and emits a single **Info** finding consolidating every open port:

- **Title**: `masscan: N TCP port(s) open on <host>`
- **Evidence**: first 20 ports (`Open ports: 22, 80, 443, ...`)
- **OWASP**: A05:2021 Security Misconfiguration
- **Confidence**: 0.9

One aggregate finding per run, never per-port — keep reports readable when a host exposes many services. Default rate is 1k pps (polite); operators who own the network tune it higher by invoking masscan directly.

## How to run

```
scorchkit run https://target.example.com --modules masscan
```

masscan resolves the target's hostname and sweeps ports 0-1023 (top-1024). 180s timeout.

## Limitations vs alternatives

- **vs `nmap`**: masscan sweeps far larger ranges per second but skips the service-version and OS-fingerprinting work nmap does. Pair them: masscan to find open ports, nmap to fingerprint them, `cve_match` to enrich. See `src/tools/nmap.rs` for the enrichment pipeline.
- **vs `naabu`**: naabu ships as a single Go binary with no dependencies and integrates naturally with the ProjectDiscovery suite (httpx, katana, nuclei). Prefer naabu when the target is a handful of hosts and you want tool-chain symmetry. Prefer masscan when you're sweeping a /16 or larger.
- Runs as root by default (raw socket access). Containerised runs need `--cap-add NET_RAW` or equivalent.
