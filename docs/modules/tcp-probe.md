# TCP Reachability Probe

**Module ID:** `tcp_probe` | **Category:** Infra (Port Scan) | **Type:** Built-in
**Source:** `src/infra/tcp_probe.rs`

## What It Does

Performs unprivileged TCP-connect probes against a configurable port list on
every IP resolved from the target. This is the privilege-free baseline for
confirming a host is reachable — no `CAP_NET_RAW`, no root. For SYN scans,
service fingerprinting, and the top-1000 port set, use the `nmap` infra
module instead.

One `Info` finding is emitted per open `ip:port`.

## What It Checks

For each IP yielded by `InfraTarget::iter_ips()` the module attempts a
`tokio::net::TcpStream::connect(ip, port)` with a per-port timeout. A
successful connect produces:

| Condition | Severity |
|-----------|----------|
| TCP connect to `ip:port` succeeded within timeout | Info (confidence 0.95) |

## Configuration

Default port list (8): `22, 80, 443, 3306, 5432, 6379, 8080, 8443`.
Default per-port timeout: `2s`.

Both are override-able via `TcpProbeConfig::with_ports(...)` /
`with_timeout(...)` when the module is constructed programmatically.

## How to Run

```
scorchkit assess 192.0.2.10 --modules tcp_probe
scorchkit assess 10.0.0.0/24 --modules tcp_probe
```

The module accepts `InfraTarget::Ip`, `InfraTarget::Cidr`,
`InfraTarget::Endpoint`, and `InfraTarget::Multi`. Pure `Host(...)` targets
without a resolved IP yield no findings today; DNS resolution is handled by
the `dns_probe` module.

## Limitations

- TCP-connect only — closed and filtered ports are indistinguishable
  (both appear as "not open").
- No service fingerprinting, banner grabbing, or version detection. That
  work lives in the `nmap` infra module, which publishes CPE-tagged
  fingerprints that the `cve_match` module consumes.
- Default port list is intentionally small; widen via `with_ports` for
  broader coverage.
- Large CIDR ranges multiply request volume (hosts × ports). Tune timeout
  and port count accordingly.

## OWASP / CWE

- Informational — open ports are not inherently a finding. Paired with
  `nmap` + `cve_match`, open ports become the seed for CPE-based CVE
  correlation.
