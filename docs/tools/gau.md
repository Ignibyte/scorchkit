# Gau Passive URL Discovery

**Module ID:** `gau` | **Category:** Recon | **Binary:** `gau`
**Source:** `src/tools/gau.rs`

## Overview

Gau (GetAllUrls) is a passive URL discovery tool that fetches known URLs from the Wayback Machine, Common Crawl, URLScan, and other passive sources. ScorchKit wraps Gau to discover historical endpoints without actively crawling the target, providing a comprehensive view of the target's URL surface area over time.

## Installation

```bash
# Go install (recommended)
go install github.com/lc/gau/v2/cmd/gau@latest

# Homebrew (macOS / Linux)
brew install gau

# Download binary from GitHub releases
# https://github.com/lc/gau/releases
```

## How ScorchKit Uses It

**Command:** `gau --subs <domain>`
**Output format:** Plain text (one URL per line)
**Timeout:** 120s (2 minutes)

The `--subs` flag includes subdomain URLs in the results. The wrapper resolves the target to a domain before passing it to Gau. Only lines starting with `http` are included in the results.

## What Gets Parsed

Gau outputs one URL per line. ScorchKit filters for lines starting with `http` and consolidates all discovered URLs into a single finding with the total count and a sample of up to 10 URLs.

## Findings Produced

| Finding | Severity | Condition |
|---------|----------|-----------|
| Historical URLs Discovered | Info | Any URLs found in passive sources |

All findings are tagged with **OWASP A05:2021 Security Misconfiguration**. Evidence includes the total URL count. These historical URLs are valuable for discovering forgotten endpoints, old admin panels, backup files, and API endpoints.

## Configuration

```toml
[tools]
gau = "/custom/path/to/gau"
```

## Standalone Usage

```bash
# Discover all known URLs for a domain (including subdomains)
gau --subs example.com

# Filter by specific providers
gau --providers wayback,commoncrawl example.com

# Output to file
gau --subs example.com -o urls.txt

# Filter by file extension
gau --subs example.com --blacklist png,jpg,gif,css
```
