# ssh-audit

SSH server hardening check — evaluates negotiated KEX algorithms, ciphers, MACs, and host keys against current best practice. License: MIT (upstream: [jtesta/ssh-audit](https://github.com/jtesta/ssh-audit)).

## Install

```
pipx install ssh-audit
# or: pip install ssh-audit
```

Verify with `scorchkit doctor`.

## What ScorchKit surfaces

The wrapper runs `ssh-audit -j <host>` (JSON output) and walks the `kex`, `key`, `enc`, `mac` arrays. Any entry whose `notes.fail` list is non-empty is treated as a definitively-weak algorithm and contributes to one aggregate finding:

- **Medium** — `ssh-audit: N weak SSH algorithm(s)` (OWASP A02:2021 Cryptographic Failures, CWE-327, confidence 0.9)
- **Info** — `ssh-audit: SSH banner on <host>` with the raw banner text, always emitted when present

The weak-algorithm finding names each offender as `kex:<name>`, `enc:<name>`, etc. Remediation recommends modern KEX / ciphers (ChaCha20-Poly1305, AES-GCM, curve25519-sha256) and sshd_config updates.

## How to run

```
scorchkit run https://target.example.com --modules ssh_audit
```

45s timeout. Target's SSH port (default 22) must be reachable.

## Limitations vs alternatives

- **Sister module to `tls_infra`** for the SSH protocol — same shape, different transport. Use both in infra assessments.
- **Warn / info items skipped**. This wrapper only surfaces `fail` entries (definitively weak); warnings on legacy-but-acceptable algorithms are omitted to keep reports focused. Run ssh-audit directly for a full report.
- **No client-side audit**. ssh-audit can audit client keys and OpenSSH user configs (`ssh-audit -c`); only server-side auditing is wrapped.
