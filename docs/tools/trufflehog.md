# Trufflehog Secret Scanner

**Module ID:** `trufflehog` | **Category:** Scanner | **Binary:** `trufflehog`
**Source:** `src/tools/trufflehog.rs`

## Overview

Trufflehog is a secret scanning tool that detects leaked API keys, credentials, and tokens in filesystems, git repositories, and other sources. ScorchKit wraps Trufflehog to identify hardcoded secrets, distinguishing between verified (confirmed active) and unverified credentials. Detected secrets are automatically redacted in findings for safe reporting.

## Installation

```bash
# Go install (recommended)
go install github.com/trufflesecurity/trufflehog/v3@latest

# Homebrew (macOS / Linux)
brew install trufflehog

# Docker
docker pull trufflesecurity/trufflehog

# Download binary from GitHub releases
# https://github.com/trufflesecurity/trufflehog/releases
```

## How ScorchKit Uses It

**Command:** `trufflehog filesystem --json --no-update <target>`
**Output format:** JSON-lines (one JSON object per detected secret)
**Timeout:** 300s (5 minutes)

Key flags:
- `filesystem` -- scan a filesystem path
- `--json` -- JSON-lines output for machine parsing
- `--no-update` -- skip automatic version update checks

## What Gets Parsed

Each JSON line represents a detected secret and is parsed for:

- `DetectorName` -- the type of secret (e.g., AWS, GitHub, Slack)
- `Verified` -- whether the secret was confirmed active (boolean)
- `Raw` -- the raw secret value (redacted in findings)
- `SourceMetadata.Data.Filesystem.file` -- the file containing the secret

Secrets are automatically redacted: only the first 4 and last 4 characters are shown, with `...` in between.

## Findings Produced

| Finding | Severity | Condition |
|---------|----------|-----------|
| Secret Detected (VERIFIED) | High | Active credential confirmed |
| Secret Detected (unverified) | Medium | Potential credential found but not confirmed |

All findings are tagged with **OWASP A07:2021 Identification and Authentication Failures** and **CWE-798** (Use of Hard-coded Credentials). Each finding includes the detector name, verification status, and source file path.

## Configuration

```toml
[tools]
trufflehog = "/custom/path/to/trufflehog"
```

## Standalone Usage

```bash
# Scan a directory for secrets
trufflehog filesystem --json /path/to/project

# Scan a git repository (includes history)
trufflehog git --json https://github.com/example/repo

# Scan only verified secrets
trufflehog filesystem --json --only-verified /path/to/project

# Scan with specific detectors
trufflehog filesystem --json --include-detectors aws,github /path/to/project

# Scan a GitHub organization
trufflehog github --org example-org --json
```
