# nmap (Infra) — Port Scan + Service Fingerprinting

**Module ID:** `nmap` | **Category:** Infra (Port Scan) | **Type:** External tool wrapper
**Source:** `src/infra/nmap.rs`

## What It Does

Runs `nmap -sV --top-ports 1000 -oX - <target>`, parses the XML output
through `parse_nmap_xml_fingerprints`, and publishes the resulting
`Vec<ServiceFingerprint>` to the scan's shared data under
`SHARED_KEY_FINGERPRINTS`. One `Info` finding is emitted per open port with
the CPE embedded as evidence when nmap produced one.

This is the infra-module counterpart to `tools::nmap::NmapModule` (the DAST
wrapper). The DAST wrapper classifies severity by port and flags outdated
versions; this infra version stays minimal because CVE correlation is the
intended consumer — the downstream `cve_match` module reads the published
fingerprints and produces the severity-graded findings.

## What It Checks

For every open port nmap reports:

| Condition | Severity | Evidence |
|-----------|----------|----------|
| Open port with service detected | Info (confidence 0.9) | CPE (when available) |

Finding title format: `Open port {port}/{protocol} ({service_name})`.
Description includes the product + version nmap identified.

## Target Handling

| `InfraTarget` variant | Passed to nmap as |
|-----------------------|-------------------|
| `Ip(…)` | IP display form |
| `Cidr(…)` | CIDR string |
| `Host(name)` / `Endpoint { host, … }` | `name` |
| `Multi([…])` | Children joined with spaces |

Endpoint's port is ignored — nmap positional targets cannot scope to a
single port.

## How to Run

```
scorchkit assess 192.0.2.10 --modules nmap
scorchkit assess example.com --modules nmap,cve_match
```

Requires the `nmap` binary on `PATH`. CLI timeout is 600 s (port scans on
a /24 with the top-1000 port set take a while).

## Limitations

- Runs `-sV` against the top 1000 ports only; there is no flag exposed
  today to widen the port range or change the scan type (SYN, XMAS, ACK).
  For that, use the DAST `nmap` tool wrapper or run nmap manually.
- XML parsing is lossy — fields nmap elides (product for obscure services)
  are left as `None`, which means `cve_match` has no CPE to correlate
  against.
- Severity is hardcoded `Info`; real risk ranking comes from feeding the
  fingerprints into `cve_match`.
- Requires network reachability to the target and the ability to complete
  TCP handshakes — stealth / evasion flags are not configured.

## OWASP / CWE

- Informational. Downstream `cve_match` findings carry the CVE severity
  and OWASP tagging.
