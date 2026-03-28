# Droopescan CMS Scanner

**Module ID:** `droopescan` | **Category:** Scanner | **Binary:** `droopescan`
**Source:** `src/tools/droopescan.rs`

## Overview

Droopescan is a plugin-based CMS (Content Management System) vulnerability scanner that supports Drupal, Joomla, WordPress, Silverstripe, and Moodle. ScorchKit wraps Droopescan to identify CMS versions, installed plugins, and interesting URLs that may indicate misconfigurations. It complements WPScan by covering additional CMS platforms beyond WordPress.

## Installation

```bash
# pip (recommended)
pip install droopescan

# pipx (isolated install)
pipx install droopescan

# From source
git clone https://github.com/SamJoan/droopescan.git
cd droopescan
pip install -r requirements.txt
```

## How ScorchKit Uses It

**Command:** `droopescan scan -u <target> --output json`
**Output format:** JSON
**Timeout:** 300s (5 minutes)

Key flags:
- `scan` -- scan subcommand
- `-u` -- target URL
- `--output json` -- JSON output format

## What Gets Parsed

The JSON output is parsed for three sections:

**CMS version (`version`):**
- The detected CMS version string

**Plugins (`plugins` array):**
- `name` -- plugin name
- `version` -- plugin version

**Interesting URLs (`interesting_urls` array):**
- `url` -- the URL of the interesting resource
- `description` -- what makes it interesting (e.g., changelog, readme, admin panel)

## Findings Produced

| Finding | Severity | Condition |
|---------|----------|-----------|
| CMS Version: {version} | Info | CMS version detected |
| Plugin: {name} {version} | Info | Plugin detected |
| Interesting: {url} | Low | Interesting URL discovered |

Interesting URL findings are tagged with **OWASP A05:2021 Security Misconfiguration**, as exposed admin interfaces, changelogs, and readme files can leak information useful to attackers.

## Configuration

```toml
[tools]
droopescan = "/custom/path/to/droopescan"
```

## Standalone Usage

```bash
# Auto-detect CMS and scan
droopescan scan -u https://example.com --output json

# Scan a specific CMS type
droopescan scan drupal -u https://example.com --output json
droopescan scan joomla -u https://example.com --output json
droopescan scan wordpress -u https://example.com --output json
droopescan scan silverstripe -u https://example.com --output json

# Scan with threading
droopescan scan -u https://example.com -t 10

# Enumerate plugins
droopescan scan drupal -u https://example.com -e p

# Enumerate themes
droopescan scan drupal -u https://example.com -e t

# Scan multiple targets
droopescan scan -U targets.txt --output json
```
