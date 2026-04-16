# onesixtyone

Fast SNMP community-string scanner — probes SNMP v1/v2c on UDP 161 with a candidate list. License: MIT (upstream: [trailofbits/onesixtyone](https://github.com/trailofbits/onesixtyone)).

## Install

```
apt install onesixtyone    # Debian / Ubuntu
```

Or build from source per upstream. Verify with `scorchkit doctor`.

## What ScorchKit surfaces

The wrapper writes a small built-in community list (`public`, `private`, `community`, `manager`, `admin`) to a temp file and runs `onesixtyone -c <file> <host>`. Every response line (format `<ip> [<community>] <sysDescr>`) is parsed for the community string, and all hits are consolidated into a single **High** finding:

- **Title**: `SNMP accessible with default community string(s) on <host>`
- **Evidence**: the working community strings (e.g. `Working communities: public, private`)
- **OWASP**: A05:2021 Security Misconfiguration
- **CWE**: 521 (Weak Password Requirements)
- **Confidence**: 0.95

Remediation: disable SNMP v1/v2c; switch to SNMPv3 with auth + privacy and a strong random community string.

## How to run

```
scorchkit run https://target.example.com --modules onesixtyone
```

45s timeout. UDP 161 must be reachable.

## Limitations vs alternatives

- **Short wordlist by design**. Five names hit the common defaults cheaply. Operators who want deep enumeration run onesixtyone directly with SecLists community-string lists.
- **SNMP v1/v2c only** — SNMPv3 uses usernames and auth algorithms, not community strings, so this scanner simply won't respond for a v3-only server (no false positive).
- **Pair with `nmap -sU -p 161`** in infra assessments to confirm the UDP port is actually open before interpreting a silent onesixtyone run.
