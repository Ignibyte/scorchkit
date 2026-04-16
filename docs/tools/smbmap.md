# smbmap

SMB share enumerator — probes the target for readable / writable shares via a null session. License: GPL-3.0 (upstream: [ShawnDEvans/smbmap](https://github.com/ShawnDEvans/smbmap)).

## Install

```
pipx install smbmap    # recommended
# or: pip install smbmap
```

Verify with `scorchkit doctor`.

## What ScorchKit surfaces

The wrapper runs `smbmap -H <host> -u anonymous -p ""` (anonymous / null-session attempt) and parses the table-style output. Each `Disk` row with a permission hint feeds one of two aggregate findings:

| Severity | Trigger | Title |
|---|---|---|
| **High** | any share lists `WRITE` permission | `Anonymous WRITE access to N SMB share(s)` |
| **Medium** | any share lists `READ` (without WRITE) | `Anonymous READ access to N SMB share(s)` |

Both findings carry:

- **OWASP**: A01:2021 Broken Access Control
- **CWE**: 284 (Improper Access Control)
- **Evidence**: the list of share names
- **Confidence**: 0.9

`NO ACCESS` rows produce no finding.

## How to run

```
scorchkit run https://target.example.com --modules smbmap
```

120s timeout. The target must have port 445 reachable.

## Limitations vs alternatives

- **vs `nxc`**: nxc (NetExec) probes multiple protocols (SMB, WinRM, MSSQL, RDP, SSH) and gives broader AD coverage; smbmap is focused on share enumeration specifically. Run both — they find different things.
- **vs `enum4linux`**: enum4linux is broader (users, groups, policies, shares) but older and less reliable; smbmap's share-permission output is cleaner for triage.
- This wrapper only tests the anonymous null session. For credentialed enumeration, run smbmap directly with `-u <user> -p <pass>`.
