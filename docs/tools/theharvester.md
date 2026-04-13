# theHarvester OSINT

**Module ID:** `theharvester` | **Category:** Recon | **Binary:** `theHarvester`
**Source:** `src/tools/theharvester.rs`

## Overview

theHarvester is an OSINT (Open Source Intelligence) tool for gathering email addresses, subdomains, hosts, and other public information about a target domain. ScorchKit wraps it to collect publicly exposed email addresses and associated hosts, which can reveal the organization's attack surface and potential phishing targets.

## Installation

```bash
# pip (recommended)
pip install theHarvester

# pipx (isolated install)
pipx install theHarvester

# From source
git clone https://github.com/laramies/theHarvester.git
cd theHarvester
pip install -r requirements.txt
```

## How ScorchKit Uses It

**Command:** `theHarvester -d <domain> -b crtsh,dnsdumpster,hackertarget -f /dev/stdout`
**Output format:** Console text (section-based)
**Timeout:** 120s (2 minutes)

Key flags:
- `-d` -- target domain
- `-b crtsh,dnsdumpster,hackertarget` -- data sources to query (certificate transparency, DNS dumps, HackerTarget)
- `-f /dev/stdout` -- output file (stdout)

**Domain requirement:** The wrapper requires a domain to be extracted from the target URL. If no domain is available, a `ScorchError::InvalidTarget` error is returned.

## What Gets Parsed

The text output is parsed section by section. The parser tracks which section it is in based on marker lines:

- `[*] Emails found:` -- switches to email collection mode
- `[*] Hosts found:` -- switches to host collection mode
- `[*]` (any other) -- resets the section

Within each section, non-empty lines that do not start with `-` are collected:
- **Emails:** Lines containing `@` are treated as email addresses
- **Hosts:** All non-empty lines in the hosts section

## Findings Produced

| Finding | Severity | Condition |
|---------|----------|-----------|
| {count} Emails Found | Info | At least one email address discovered |
| {count} Hosts Found | Info | At least one host discovered |

Each finding includes:
- **Evidence:** Newline-separated list of all discovered emails or hosts

## Configuration

```toml
[tools]
theHarvester = "/custom/path/to/theHarvester"
```

Note: The binary name is case-sensitive (`theHarvester`, not `theharvester`).

## Standalone Usage

```bash
# Basic search with default sources
theHarvester -d example.com -b crtsh,dnsdumpster,hackertarget

# Search with all sources
theHarvester -d example.com -b all

# Limit results
theHarvester -d example.com -b crtsh -l 200

# Save to XML file
theHarvester -d example.com -b all -f results.xml

# DNS brute-force
theHarvester -d example.com -b all -c

# Use Shodan
theHarvester -d example.com -b shodan

# Search specific sources with API keys configured
theHarvester -d example.com -b virustotal,securitytrails
```
