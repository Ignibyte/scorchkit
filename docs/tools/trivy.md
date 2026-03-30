# Trivy Vulnerability Scanner

**Module ID:** `trivy` | **Category:** Scanner | **Binary:** `trivy`
**Source:** `src/tools/trivy.rs`

## Overview

Trivy is a comprehensive security scanner from Aqua Security for finding vulnerabilities in container images, filesystems, git repositories, and infrastructure-as-code. ScorchKit wraps Trivy in filesystem mode to scan for known vulnerabilities in dependencies, producing per-CVE findings with package names, installed versions, and available fixes.

## Installation

```bash
# Debian / Ubuntu
sudo apt install trivy

# Homebrew (macOS / Linux)
brew install trivy

# RPM-based
sudo yum install trivy

# Docker
docker pull aquasec/trivy

# Install script
curl -sfL https://raw.githubusercontent.com/aquasecurity/trivy/main/contrib/install.sh | sh
```

## How ScorchKit Uses It

**Command:** `trivy fs --format json --quiet <target>`
**Output format:** JSON (structured vulnerability report)
**Timeout:** 300s (5 minutes)

Key flags:
- `fs` -- filesystem scanning mode
- `--format json` -- JSON output for machine parsing
- `--quiet` -- suppress progress bar and informational output

The wrapper resolves the target to a domain or path before passing it to Trivy.

## What Gets Parsed

Trivy outputs a JSON object with a `Results` array. Each result contains a `Target` (e.g., `package-lock.json`) and a `Vulnerabilities` array. For each vulnerability:

- `VulnerabilityID` -- CVE identifier (e.g., CVE-2023-1234)
- `Severity` -- CRITICAL, HIGH, MEDIUM, LOW, or UNKNOWN
- `Title` -- human-readable vulnerability description
- `PkgName` -- the affected package name
- `InstalledVersion` -- the currently installed version
- `FixedVersion` -- the version containing the fix

## Findings Produced

Each vulnerability becomes its own finding:

| Severity | Condition |
|----------|-----------|
| Critical | Trivy severity = CRITICAL |
| High | Trivy severity = HIGH |
| Medium | Trivy severity = MEDIUM |
| Low | Trivy severity = LOW |
| Info | Unknown or informational severity |

All findings are tagged with **OWASP A06:2021 Vulnerable and Outdated Components** and **CWE-1104**. Remediation includes the specific version upgrade path for each vulnerable package.

## Configuration

```toml
[tools]
trivy = "/custom/path/to/trivy"
```

## Standalone Usage

```bash
# Scan filesystem for vulnerabilities
trivy fs --format json --quiet .

# Scan a container image
trivy image --format json nginx:latest

# Scan with severity filter
trivy fs --severity CRITICAL,HIGH .

# Scan a git repository
trivy repo https://github.com/example/project

# Scan infrastructure-as-code
trivy config --format json ./terraform/
```
