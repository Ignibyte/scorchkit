# Hydra Login Tester

**Module ID:** `hydra` | **Category:** Scanner | **Binary:** `hydra`
**Source:** `src/tools/hydra.rs`

## Overview

THC Hydra is a fast network login cracker supporting numerous protocols. ScorchKit wraps Hydra for a very limited, safe purpose: testing whether the target's admin panel uses default credentials (admin/admin). This is a single-attempt check, not a brute-force attack. Finding default credentials is a critical vulnerability that indicates the application was deployed without basic security hardening.

## Installation

```bash
# Debian / Ubuntu
sudo apt install hydra

# macOS
brew install hydra

# Fedora / RHEL
sudo dnf install hydra

# From source
git clone https://github.com/vanhauser-thc/thc-hydra.git
cd thc-hydra && ./configure && make && sudo make install
```

## How ScorchKit Uses It

**Command:** `hydra -l admin -p admin -s <port> -f <target> <protocol> /admin`
**Output format:** Console text
**Timeout:** 30s

Key flags:
- `-l admin` -- single login username (admin)
- `-p admin` -- single password (admin)
- `-s <port>` -- target port
- `-f` -- stop on first valid login found
- `<protocol>` -- `https-get` or `http-get` based on target scheme
- `/admin` -- path to test

This is deliberately conservative: a single credential pair tested against a single path. The wrapper determines the protocol (http-get vs https-get) based on whether the target uses HTTPS.

## What Gets Parsed

The wrapper scans each output line for the pattern containing both `login:` and `password:`, which indicates Hydra found valid credentials.

## Findings Produced

| Finding | Severity | CWE | Condition |
|---------|----------|-----|-----------|
| Default Credentials Found | Critical | 798 | Hydra output contains a valid login line |

The finding includes:
- **OWASP:** A07:2021 Identification and Authentication Failures
- **CWE:** 798 (Use of Hard-coded Credentials)
- **Remediation:** Change default credentials immediately
- **Evidence:** The raw Hydra output line showing the successful login

If no default credentials are found, no findings are produced (clean result).

## Configuration

```toml
[tools]
hydra = "/custom/path/to/hydra"
```

## Standalone Usage

```bash
# Test single credentials against HTTP basic auth
hydra -l admin -p admin example.com http-get /admin

# Brute-force SSH with a password list
hydra -l root -P passwords.txt ssh://example.com

# Test multiple users/passwords against a web form
hydra -L users.txt -P passwords.txt example.com http-post-form \
  "/login:user=^USER^&pass=^PASS^:Invalid credentials"

# Test FTP with common defaults
hydra -l anonymous -p anonymous ftp://example.com

# Limit threads and add delay
hydra -l admin -P passwords.txt -t 4 -W 1 example.com http-get /admin

# Test against a specific port
hydra -l admin -p admin -s 8080 example.com http-get /
```
