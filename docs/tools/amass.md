# Amass Subdomain Enumerator

**Module ID:** `amass` | **Category:** Recon | **Binary:** `amass`
**Source:** `src/tools/amass.rs`

## Overview

OWASP Amass is an advanced subdomain enumeration tool that uses multiple data sources, DNS resolution, and network mapping techniques to discover subdomains. ScorchKit wraps Amass in passive mode to discover the target's subdomain footprint without actively probing the target infrastructure. This helps identify the full attack surface, including forgotten or shadow IT assets.

## Installation

```bash
# Go install (recommended)
go install -v github.com/owasp-amass/amass/v4/...@master

# Homebrew (macOS / Linux)
brew install amass

# Snap
sudo snap install amass

# Download binary from GitHub releases
# https://github.com/owasp-amass/amass/releases
```

## How ScorchKit Uses It

**Command:** `amass enum -passive -d <domain> -json /dev/stdout -timeout 5`
**Output format:** JSON-lines (one JSON object per line)
**Timeout:** 360s (6 minutes)

Key flags:
- `enum` -- enumeration subcommand
- `-passive` -- passive mode only (no DNS brute-forcing or active probing)
- `-d` -- target domain
- `-json /dev/stdout` -- JSON output to stdout
- `-timeout 5` -- 5-minute timeout for the enumeration

**Domain requirement:** The wrapper requires a domain to be extracted from the target URL. If no domain is available, a `ScorchError::InvalidTarget` error is returned.

## What Gets Parsed

Each JSON line is parsed for the `name` field, which contains a discovered subdomain. Duplicates are removed. The collected subdomains are sorted alphabetically and truncated to the first 100 entries for the evidence field.

## Findings Produced

| Finding | Severity | Condition |
|---------|----------|-----------|
| {count} Subdomains Found (Amass) | Info | At least one subdomain discovered |

The finding includes:
- **Title:** `{count} Subdomains Found (Amass)`
- **Description:** Summary with total count
- **Evidence:** Newline-separated list of discovered subdomains (up to 100)

No findings are produced if zero subdomains are found.

## Configuration

```toml
[tools]
amass = "/custom/path/to/amass"
```

## Standalone Usage

```bash
# Passive subdomain enumeration with JSON output
amass enum -passive -d example.com -json /dev/stdout

# Active enumeration (DNS brute-force + passive)
amass enum -d example.com

# Passive with specific data sources
amass enum -passive -d example.com -src

# Save results to file
amass enum -passive -d example.com -o subdomains.txt

# Use configuration file for API keys
amass enum -passive -d example.com -config config.yaml

# Intel mode (discover root domains from an organization)
amass intel -org "Example Corp"

# Visualize results
amass viz -d example.com -dot network.dot
```
