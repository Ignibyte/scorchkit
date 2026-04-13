# Prowler Cloud Scanner

**Module ID:** `prowler` | **Category:** Scanner | **Binary:** `prowler`
**Source:** `src/tools/prowler.rs`

## Overview

Prowler is an open-source cloud security assessment tool supporting AWS, Azure, and GCP. ScorchKit wraps Prowler to scan cloud infrastructure for misconfigurations including public S3 buckets, overly permissive IAM policies, security group issues, unencrypted storage, and metadata endpoint exposure. Requires valid cloud credentials configured in the environment.

## Installation

```bash
# pip (recommended)
pip install prowler

# Homebrew (macOS)
brew install prowler

# Docker
docker pull toniblyx/prowler

# From source
git clone https://github.com/prowler-cloud/prowler.git
cd prowler && pip install .
```

Requires configured cloud credentials (e.g., `AWS_ACCESS_KEY_ID`/`AWS_SECRET_ACCESS_KEY` for AWS).

## How ScorchKit Uses It

**Command:** `prowler -M json-ocsf --no-banner -q`
**Output format:** JSON (OCSF format -- Open Cybersecurity Schema Framework)
**Timeout:** 600s (10 minutes)

Key flags:
- `-M json-ocsf` -- output in OCSF JSON format for structured parsing
- `--no-banner` -- suppress banner output
- `-q` -- quiet mode

The wrapper supports both JSON array and JSON-lines output formats as a fallback.

## What Gets Parsed

Each JSON object in the output is checked for `status_id` (where `1` = PASS). Failed checks are parsed for:

- `finding_info.title` or `metadata.event_code` -- the check title
- `message` or `status_detail` -- detailed description
- `severity` -- severity level (critical/high/medium/low/informational)
- `resources[].group.name` -- the cloud service name (e.g., s3, iam, cloudtrail)

## Findings Produced

Prowler produces findings at all severity levels depending on which checks fail:

| Severity | Example Checks |
|----------|---------------|
| Critical | Root account without MFA, public RDS instances |
| High | Public S3 buckets, overly permissive security groups |
| Medium | CloudTrail disabled, unencrypted EBS volumes |
| Low | Minor policy deviations |

All findings are tagged with **OWASP A05:2021 Security Misconfiguration**. Evidence includes the cloud service name and severity level.

## Configuration

```toml
[tools]
prowler = "/custom/path/to/prowler"
```

## Standalone Usage

```bash
# Full AWS scan with OCSF JSON output
prowler -M json-ocsf --no-banner

# Scan specific AWS services
prowler -s s3,iam,ec2

# Scan Azure
prowler azure -M json-ocsf

# Scan GCP
prowler gcp -M json-ocsf

# Filter by severity
prowler --severity critical,high
```
