# kerbrute

Kerberos pre-auth user enumerator — confirms the existence of accounts against an Active Directory domain controller without needing credentials. License: Apache-2.0 (upstream: [ropnop/kerbrute](https://github.com/ropnop/kerbrute)).

## Install

```
go install github.com/ropnop/kerbrute@latest
```

Verify with `scorchkit doctor`.

## What ScorchKit surfaces

The wrapper ships a tiny built-in user list (10 common account names: `administrator`, `admin`, `guest`, `krbtgt`, `service`, `test`, `user`, `backup`, `operator`, `support`) written to a temp file and passed to `kerbrute userenum --dc <host> --domain <host> <userlist>`.

It parses lines containing `VALID USERNAME:` and consolidates into a single **Medium** finding when any users exist:

- **Title**: `kerbrute: N valid Kerberos user(s) enumerated`
- **Evidence**: the validated usernames
- **OWASP**: A07:2021 Identification and Authentication Failures
- **CWE**: 204 (Observable Response Discrepancy)
- **Confidence**: 0.85

## How to run

```
scorchkit run https://target.example.com --modules kerbrute
```

60s timeout. Port 88 (Kerberos) must be reachable.

## Limitations vs alternatives

- **Built-in wordlist is tiny by design**. Ten names gets you signal without noise or load. Operators hunting for broader enumeration run kerbrute directly with SecLists / usernames-from-OSINT wordlists (`kerbrute userenum --dc <dc> --domain <domain> seclists/Usernames/xato-net-10-million-usernames.txt`).
- **v1 does `userenum` only**. kerbrute also supports `passwordspray` (single password against a user list) and `bruteforce` (multiple passwords). Both are noisy and potentially account-locking — left as direct-invoke operations.
- Use alongside `nxc` (SMB banner + null session) and `smbmap` (share enumeration) for a baseline AD assessment.
