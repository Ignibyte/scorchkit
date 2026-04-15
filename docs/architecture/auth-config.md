# Authenticated Network Scanning — `[network_credentials]`

Operator-facing guide to ScorchKit's credential plumbing for SSH, SMB, SNMP, and Kerberos probes. Shipped in WORK-146 and backed by the architecture decision `infra.network-credentials`.

## TL;DR

```toml
# scorchkit.toml

[network_credentials]
ssh_user          = "root"
ssh_key_path      = "/home/alice/.ssh/id_ed25519"
smb_username      = "DOMAIN\\alice"
smb_password      = "s3cret"        # redacted in logs; ship via env in CI
snmp_community    = "private"       # redacted in logs
kerberos_principal = "alice@CORP.EXAMPLE"
```

Or via environment variables (wins over the config file):

```bash
export SCORCHKIT_SMB_USERNAME="DOMAIN\\alice"
export SCORCHKIT_SMB_PASSWORD="s3cret"
export SCORCHKIT_SNMP_COMMUNITY="private"
scorchkit infra example.com
```

## Fields

| Field | TOML Type | Env Var | Redacted in logs | Used by |
|-------|-----------|---------|:----------------:|---------|
| `ssh_user` | `Option<String>` | `SCORCHKIT_SSH_USER` | no | future SSH login probe |
| `ssh_key_path` | `Option<String>` | `SCORCHKIT_SSH_KEY_PATH` | no (path only) | future SSH login probe |
| `smb_username` | `Option<String>` | `SCORCHKIT_SMB_USERNAME` | no | `tools::nxc`, `tools::smbmap` |
| `smb_password` | `Option<String>` | `SCORCHKIT_SMB_PASSWORD` | **yes** | `tools::nxc`, `tools::smbmap` |
| `snmp_community` | `Option<String>` | `SCORCHKIT_SNMP_COMMUNITY` | **yes** | future SNMP walk probe |
| `kerberos_principal` | `Option<String>` | `SCORCHKIT_KERBEROS_PRINCIPAL` | no | `tools::kerbrute` |

All fields are optional. When every field is unset, scans run unauthenticated — the pre-WORK-146 behavior.

## Precedence

1. **Environment variable (set + non-empty)** — wins.
2. **Config file `[network_credentials]` block.**
3. **Default** — `None`.

Env vars set to empty string (`SCORCHKIT_SMB_PASSWORD=""`) are treated as *unset*. This matches the `SCORCHKIT_NVD_API_KEY` pattern shipped in WORK-103b and handles the common CI scenario where a variable is exported unconditionally even when the secret is absent.

## Where to put secrets

| Deployment | Recommendation |
|-----------|----------------|
| Local workstation | Config file; keep outside version control (add `scorchkit.toml` to `.gitignore`). |
| CI / pipeline | Environment variables, pulled from a secret manager (GitHub Actions secrets, Vault, AWS Secrets Manager, etc.). The env-var path lets you keep `scorchkit.toml` in the repo with everything except secrets. |
| Shared workstation | Env vars exported by a sibling process, never written to disk. |
| Kubernetes / containers | Mount a secret as an env var or use the [downward API]; do not bake into image layers. |

[downward API]: https://kubernetes.io/docs/concepts/workloads/pods/downward-api/

## Log-level guarantees

Tool wrappers that pass secrets via argv (currently `nxc` and `smbmap`) log a **redacted** command line at `debug!` level. Example:

```
DEBUG scorchkit::tools::nxc: nxc: smb example.com -u alice -p *** --no-progress
```

The literal `-p` and `--password` / `-c` and `--community` flag values are replaced with `***` before log emission. The argv passed to the actual subprocess contains the real secret — we can't redact what the external tool reads from stdin / argv, only what ScorchKit writes to its own log.

The `NetworkCredentials` struct itself has a hand-rolled `Debug` impl that redacts `smb_password` and `snmp_community` so any `tracing::debug!("{:?}", creds)` anywhere in the codebase is automatically safe.

## Tool-wrapper credential support matrix

| Wrapper | Credential(s) used | No-credentials fallback |
|---------|--------------------|-------------------------|
| `tools::nxc` | `smb_username`, `smb_password` | `-u '' -p ''` (null session) |
| `tools::smbmap` | `smb_username`, `smb_password` | `-u anonymous -p ''` |
| `tools::kerbrute` | `kerberos_principal` (domain extracted) | `--domain <target host>` |

Other wrappers (e.g. `tools::onesixtyone`, `tools::ssh-audit`) have not yet been updated; they'll pick up credential support in follow-up pipelines.

## Non-goals

- **Secret encryption at rest.** Secrets live in plaintext in the config file or the environment. Operators who want encrypted secrets should use the env-var path with a secret manager. Adding age/rage encryption is tracked as a separate ticket.
- **Native credentialed probe modules.** SSH login, SMB mount, SNMP walk native probes are planned follow-ups. WORK-146 shipped the foundation + proof-of-pattern updates to the three existing external-tool wrappers.
- **Credential rotation / TTL.** Credentials are loaded once at scan start. Operators rotate by restarting ScorchKit.

## Programmatic access

```rust
use scorchkit::prelude::*;

let config = AppConfig::load(Some(&std::path::PathBuf::from("scorchkit.toml")))?;
let creds = NetworkCredentials::from_config_with_env(&config.network_credentials);

// Safe to log — Debug redacts secrets:
tracing::debug!(?creds, "resolved credentials");

// Short-circuit when no credentials are configured:
if creds.is_empty() {
    // unauthenticated scan path
}
# Ok::<(), scorchkit::ScorchError>(())
```
