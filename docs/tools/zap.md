# OWASP ZAP Scanner

**Module ID:** `zap` | **Category:** Scanner | **Binary:** `zap-cli`
**Source:** `src/tools/zap.rs`

## Overview

OWASP ZAP (Zed Attack Proxy) is a widely-used open-source web application security scanner. ScorchKit wraps the `zap-cli` command-line interface to perform automated active scanning, including spidering and active vulnerability testing. ZAP provides deep web application testing capabilities including injection testing, authentication bypass checks, and security header analysis.

## Installation

```bash
# Debian / Ubuntu
sudo apt install zaproxy

# macOS
brew install --cask owasp-zap

# Snap
sudo snap install zaproxy --classic

# Docker
docker pull ghcr.io/zaproxy/zaproxy:stable

# zap-cli (Python wrapper)
pip install zapcli
```

## How ScorchKit Uses It

**Command:** `zap-cli quick-scan --self-contained --spider -r -o json <target>`
**Output format:** JSON
**Timeout:** 600s (10 minutes)

Key flags:
- `quick-scan` -- automated scan mode
- `--self-contained` -- start and stop ZAP automatically
- `--spider` -- spider the target before scanning
- `-r` -- run active scan after spidering
- `-o json` -- JSON output format

## What Gets Parsed

The JSON output is parsed for alert objects from either `json["alerts"]` or `json["site"][0]["alerts"]`. For each alert:

- `name` or `alert` -- the alert title
- `desc` or `description` -- detailed description
- `riskcode` or `risk` -- risk level (0-3)
- `url` -- the affected URL
- `solution` -- recommended fix
- `cweid` or `cwe` -- CWE identifier

## Findings Produced

ZAP alerts are mapped to ScorchKit severities by risk code:

| Risk Code | Severity |
|-----------|----------|
| 3 | High |
| 2 | Medium |
| 1 | Low |
| 0 / other | Info |

Each finding includes:
- **Title:** `ZAP: {alert name}`
- **OWASP:** A05:2021 Security Misconfiguration (default)
- **CWE:** Extracted from alert when available
- **Remediation:** Populated from ZAP's solution field

## Configuration

```toml
[tools]
zap-cli = "/custom/path/to/zap-cli"
```

## Standalone Usage

```bash
# Quick scan with JSON output
zap-cli quick-scan --self-contained --spider -r -o json https://example.com

# Start ZAP daemon and scan separately
zap-cli start
zap-cli open-url https://example.com
zap-cli spider https://example.com
zap-cli active-scan https://example.com
zap-cli alerts -f json
zap-cli shutdown

# Docker-based scan
docker run -t ghcr.io/zaproxy/zaproxy:stable zap-baseline.py -t https://example.com -J report.json
```
