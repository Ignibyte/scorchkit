# WPScan WordPress Scanner

**Module ID:** `wpscan` | **Category:** Scanner | **Binary:** `wpscan`
**Source:** `src/tools/wpscan.rs`

## Overview

WPScan is a dedicated WordPress security scanner that checks for vulnerable WordPress core versions, plugins, and themes. ScorchKit wraps WPScan to provide targeted vulnerability assessment for WordPress sites, identifying outdated components and known security issues specific to the WordPress ecosystem.

## Installation

```bash
# Ruby gem (recommended)
gem install wpscan

# Docker
docker pull wpscanteam/wpscan

# Debian / Ubuntu (if available)
sudo apt install wpscan

# macOS
brew install wpscan
```

A WPScan API token (free tier available) enhances results with vulnerability data:
```bash
export WPSCAN_API_TOKEN="your_token_here"
```

## How ScorchKit Uses It

**Command:** `wpscan --url <target> --format json --no-banner --random-user-agent`
**Output format:** JSON
**Timeout:** 300s (5 minutes)

Key flags:
- `--url` -- target WordPress site URL
- `--format json` -- machine-parseable JSON output
- `--no-banner` -- suppress the WPScan banner
- `--random-user-agent` -- randomize User-Agent to avoid simple blocking

## What Gets Parsed

The JSON output is parsed for two main sections:

**WordPress version (`version` object):**
- `number` -- the detected WordPress version string
- `vulnerabilities[]` -- known vulnerabilities for this version, each with:
  - `title` -- vulnerability title
  - `vuln_type` -- type of vulnerability
  - `fixed_in` -- version that fixes the issue

**Plugins (`plugins` object):**
- Each plugin is keyed by name, containing:
  - `vulnerabilities[]` -- known vulnerabilities for the plugin version, each with:
    - `title` -- vulnerability title
    - `fixed_in` -- version that fixes the issue

## Findings Produced

| Finding | Severity | Condition |
|---------|----------|-----------|
| WordPress {version} Detected | Info | WordPress version identified |
| WP: {vulnerability title} | High | Core WordPress vulnerability found |
| WP Plugin {name}: {vulnerability title} | High | Plugin vulnerability found |

Version and plugin vulnerability findings include:
- **OWASP:** A06:2021 Vulnerable and Outdated Components
- **Remediation:** "Update WordPress to {fixed_in} or later" / "Update {plugin} to {fixed_in} or later"

## Configuration

```toml
[tools]
wpscan = "/custom/path/to/wpscan"
```

## Standalone Usage

```bash
# Basic scan with JSON output
wpscan --url https://example.com --format json --no-banner

# Scan with API token for vulnerability data
wpscan --url https://example.com --api-token YOUR_TOKEN --format json

# Enumerate users
wpscan --url https://example.com -e u

# Enumerate all plugins (aggressive)
wpscan --url https://example.com -e ap --plugins-detection aggressive

# Enumerate vulnerable plugins and themes
wpscan --url https://example.com -e vp,vt

# Password brute force
wpscan --url https://example.com -U admin -P passwords.txt
```
