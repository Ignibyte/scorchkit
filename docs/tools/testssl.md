# testssl.sh TLS Analyzer

**Module ID:** `testssl` | **Category:** Scanner | **Binary:** `testssl.sh`
**Source:** `src/tools/testssl.rs`

## Overview

testssl.sh is a comprehensive command-line tool for checking TLS/SSL configurations. It tests for protocol support, cipher suites, known vulnerabilities (BEAST, BREACH, POODLE, Heartbleed, CRIME, ROBOT, etc.), and certificate issues. ScorchKit wraps it as an alternative or complement to SSLyze, providing a second opinion on TLS security posture.

## Installation

```bash
# Debian / Ubuntu
sudo apt install testssl.sh

# macOS
brew install testssl

# Git clone (universal)
git clone --depth 1 https://github.com/drwetter/testssl.sh.git
# Binary is at testssl.sh/testssl.sh

# Docker
docker pull drwetter/testssl.sh
```

## How ScorchKit Uses It

**Command:** `testssl.sh --jsonfile /dev/stdout --quiet <domain:port>`
**Output format:** JSON-lines (one JSON object per line)
**Timeout:** 300s (5 minutes)

Key flags:
- `--jsonfile /dev/stdout` -- output JSON to stdout
- `--quiet` -- suppress banner and progress output

The target is formatted as `domain:port`.

## What Gets Parsed

Each JSON line is parsed for:

- `id` -- the test identifier (e.g., `SSLv2`, `BEAST`, `heartbleed`)
- `severity` -- testssl.sh's own severity rating (CRITICAL, HIGH, MEDIUM, LOW, OK, INFO)
- `finding` -- human-readable description of the finding

Lines with severity `OK` or `INFO` are skipped (they indicate passing tests). Only findings with actual issues are included.

## Findings Produced

testssl.sh severities are mapped directly:

| testssl.sh Severity | ScorchKit Severity |
|---------------------|-------------------|
| CRITICAL | Critical |
| HIGH | High |
| MEDIUM | Medium |
| LOW | Low |
| OK / INFO | Skipped |

Each finding includes:
- **Title:** `testssl: {test_id}`
- **Evidence:** `{test_id}: {finding_text}`
- **OWASP:** A02:2021 Cryptographic Failures

## Configuration

```toml
[tools]
"testssl.sh" = "/custom/path/to/testssl.sh"
```

## Standalone Usage

```bash
# Full test with JSON output to stdout
testssl.sh --jsonfile /dev/stdout example.com

# Full test with HTML report
testssl.sh --htmlfile report.html example.com

# Test specific port
testssl.sh example.com:8443

# Check only for vulnerabilities
testssl.sh --vulnerable example.com

# Check only cipher suites
testssl.sh --cipher-per-proto example.com

# Check only protocols
testssl.sh --protocols example.com

# Parallel testing of multiple hosts
testssl.sh --file hosts.txt --jsonfile results.json

# Docker usage
docker run --rm drwetter/testssl.sh example.com
```
