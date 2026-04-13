# Katana Web Crawler

**Module ID:** `katana` | **Category:** Recon | **Binary:** `katana`
**Source:** `src/tools/katana.rs`

## Overview

Katana is a next-generation web crawler from ProjectDiscovery that handles modern JavaScript-heavy single-page applications via headless browser rendering. ScorchKit wraps Katana to discover endpoints that traditional crawlers miss, including dynamically generated links, API calls made by JavaScript, and routes in SPA frameworks.

## Installation

```bash
# Go install (recommended)
go install github.com/projectdiscovery/katana/cmd/katana@latest

# Homebrew (macOS / Linux)
brew install katana

# Download binary from GitHub releases
# https://github.com/projectdiscovery/katana/releases
```

## How ScorchKit Uses It

**Command:** `katana -u <target> -json -silent -depth 3 -no-color`
**Output format:** JSON-lines (one JSON object per line)
**Timeout:** 300s (5 minutes)

Key flags:
- `-json` -- JSON-lines output for machine parsing
- `-silent` -- suppress banner and informational output
- `-depth 3` -- crawl up to 3 levels deep
- `-no-color` -- disable ANSI color codes

## What Gets Parsed

Each JSON line is parsed for endpoint URLs via two possible paths:

- `request.endpoint` -- the primary endpoint field
- `endpoint` -- fallback field for simpler output formats

All discovered URLs are consolidated into a single finding with the total count and a sample of up to 10 endpoints.

## Findings Produced

| Finding | Severity | Condition |
|---------|----------|-----------|
| Endpoints Discovered | Info | Any endpoints found via crawling |

All findings are tagged with **OWASP A05:2021 Security Misconfiguration**. Evidence includes the total URL count. Discovered endpoints feed into subsequent scanning modules for deeper analysis.

## Configuration

```toml
[tools]
katana = "/custom/path/to/katana"
```

## Standalone Usage

```bash
# Crawl with JSON output
katana -u https://example.com -json -silent

# Deeper crawl with headless browser
katana -u https://example.com -depth 5 -headless

# Crawl with scope control
katana -u https://example.com -fs fqdn

# Output to file with field selection
katana -u https://example.com -f url -o endpoints.txt

# Crawl with custom headers
katana -u https://example.com -H "Authorization: Bearer token123"
```
