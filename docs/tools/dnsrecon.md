# dnsrecon DNS Enumerator

**Module ID:** `dnsrecon` | **Category:** Recon | **Binary:** `dnsrecon`
**Source:** `src/tools/dnsrecon.rs`

## Overview

dnsrecon is a comprehensive DNS enumeration tool that performs zone transfers, reverse lookups, SRV record discovery, and brute-force subdomain enumeration. ScorchKit wraps dnsrecon to perform deep DNS analysis beyond what the built-in recon modules provide, identifying exposed DNS records and dangerous misconfigurations like permitted zone transfers.

## Installation

```bash
# Debian / Ubuntu
sudo apt install dnsrecon

# pip (Python)
pip install dnsrecon

# macOS
brew install dnsrecon

# Kali Linux (pre-installed)
```

## How ScorchKit Uses It

**Command:** `dnsrecon -d <domain> -t std --json -`
**Output format:** JSON array (streamed to stdout via `--json -`)
**Timeout:** 180s (3 minutes)

The wrapper resolves the target to a domain before passing it to dnsrecon. The `-t std` flag runs a standard enumeration covering SOA, NS, A, AAAA, MX, TXT, and other common record types.

## What Gets Parsed

ScorchKit parses the JSON array output, extracting record objects with a `type` field. Supported record types: A, AAAA, MX, NS, SOA, TXT, CNAME, SRV, PTR. For each record, the following attributes are extracted:

- `type` -- the DNS record type
- `name` -- the record name (e.g., example.com)
- `address` -- the resolved IP address or value
- `target` -- the target hostname (for MX, NS, CNAME, SRV records)

The parser also checks for zone transfer (AXFR) success indicators in info-type records.

## Findings Produced

| Finding | Severity | Condition |
|---------|----------|-----------|
| DNS Zone Transfer Possible | Medium | AXFR transfer succeeded (CWE-200) |
| DNS Records Enumerated | Info | Any DNS records discovered |

Zone transfer findings are tagged with **OWASP A05:2021 Security Misconfiguration** and **CWE-200**. DNS record findings include a sample of up to 10 records.

## Configuration

```toml
[tools]
dnsrecon = "/custom/path/to/dnsrecon"
```

## Standalone Usage

```bash
# Standard DNS enumeration with JSON output
dnsrecon -d example.com -t std --json -

# Zone transfer check
dnsrecon -d example.com -t axfr

# Brute-force subdomain enumeration
dnsrecon -d example.com -t brt -D /path/to/wordlist.txt

# Reverse lookup on a CIDR range
dnsrecon -r 192.168.1.0/24
```
