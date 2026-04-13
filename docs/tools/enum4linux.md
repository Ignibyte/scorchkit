# enum4linux SMB Enumerator

**Module ID:** `enum4linux` | **Category:** Scanner | **Binary:** `enum4linux`
**Source:** `src/tools/enum4linux.rs`

## Overview

enum4linux is a tool for enumerating information from Windows and Samba hosts. ScorchKit wraps it to discover SMB shares, enumerate users via RID cycling, extract group membership, and retrieve password policies. This is essential for assessing Windows/Samba host exposure and identifying weak authentication configurations.

## Installation

```bash
# Debian / Ubuntu
sudo apt install enum4linux

# Kali Linux (pre-installed)

# From source
git clone https://github.com/CiscoCXSecurity/enum4linux.git
```

Requires `smbclient`, `rpcclient`, `net`, and `nmblookup` from the Samba suite.

## How ScorchKit Uses It

**Command:** `enum4linux -a <target>`
**Output format:** Plain text (section-delimited output)
**Timeout:** 300s (5 minutes)

The `-a` flag runs a full enumeration including shares, users, groups, password policy, and OS information. The wrapper resolves the target to a domain or IP before passing it to enum4linux.

## What Gets Parsed

ScorchKit parses the text output by extracting three key sections:

- **Share Enumeration** -- table of SMB share names parsed from the `Sharename / Type` header
- **RID Cycling** -- usernames extracted from lines matching `DOMAIN\username (Local User)` or `(Domain User)` patterns
- **Password Policy** -- policy details extracted from the `Password Info` section

## Findings Produced

| Finding | Severity | Condition |
|---------|----------|-----------|
| SMB Shares Enumerated | Medium | One or more shares discovered (CWE-200) |
| Users Enumerated via RID Cycling | Medium | Usernames extracted via RID cycling (CWE-200) |
| Password Policy Retrieved | Medium | Domain password policy accessible (CWE-521) |

Share and user findings are tagged with **OWASP A01:2021 Broken Access Control**. Password policy findings are tagged with **OWASP A07:2021 Identification and Authentication Failures**.

## Configuration

```toml
[tools]
enum4linux = "/custom/path/to/enum4linux"
```

## Standalone Usage

```bash
# Full enumeration
enum4linux -a 10.0.0.1

# Share enumeration only
enum4linux -S 10.0.0.1

# User enumeration via RID cycling
enum4linux -r 10.0.0.1

# Specify credentials
enum4linux -u admin -p password -a 10.0.0.1
```
