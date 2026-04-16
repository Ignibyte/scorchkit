# nxc (NetExec)

The modern fork of CrackMapExec — the standard pentest tool for SMB and Active Directory assessment. License: BSD-2-Clause (upstream: [Pennyw0rth/NetExec](https://github.com/Pennyw0rth/NetExec)).

## Install

```
pipx install git+https://github.com/Pennyw0rth/NetExec
```

Verify with `scorchkit doctor`.

## What ScorchKit surfaces

The v1 wrapper runs `nxc smb <host> -u "" -p "" --no-progress` and parses the text output for two signals:

- **Medium** — `SMB Null Session Permitted` (CWE-521, A07:2021 Identification and Authentication Failures) when nxc returns a `[+]` success line for the empty-credential probe
- **Info** — `nxc: SMB host info for <host>` with the SMB banner (OS / hostname / domain) whenever nxc prints any `SMB` line

Confidence: 0.85. Remediation on the null-session finding points operators at `RestrictAnonymous = 2` (or the platform equivalent).

## How to run

```
scorchkit run https://target.example.com --modules nxc
```

60s timeout. Port 445 must be reachable.

## Limitations vs alternatives

- **Scope**: v1 covers the SMB protocol only. nxc also supports WinRM, MSSQL, RDP, SSH, and LDAP; future ScorchKit passes can add these. For now, operators who need those protocols invoke nxc directly.
- **vs `smbmap`**: smbmap digs into share-level permissions; nxc v1 here is a lighter probe for null-session + host banner. They complement each other — run both in AD assessments.
- **vs `enum4linux`**: nxc is the current best-in-class replacement; enum4linux is kept for backwards compatibility.
