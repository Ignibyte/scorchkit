# Configuration

`AppConfig` is the serialized input to the policy-gated engine. Every section has operational
defaults, but the absence of `[engagement]` is intentional: configuration can load and read-only
commands can run, while every scan family fails closed.

## Discovery order

`AppConfig::load` uses one file:

1. an explicit `--config <path>`, which must exist and be a regular file;
2. `scorchkit.toml` in the current directory;
3. legacy `config.toml` in the current directory;
4. in-memory defaults when none exists.

An explicit missing path is an error. ScorchKit does not silently replace a mistyped configuration
with defaults.

## Safe generation

```bash
scorchkit init https://owned.example
```

This sends no HTTP request. It parses the target, performs a five-second DNS lookup, pins every
current address, and writes a quick-profile `scorchkit.toml`. The generated engagement grants only
`dast-scan`, `external-tool`, `passive`, and `active-safe`. The quick profile itself does not execute
external tools.

Running `scorchkit init` without a target writes the legacy default `config.toml`. It has no
engagement and therefore authorizes no scan.

## Top-level sections

| Section | Purpose |
|---|---|
| `engagement` | authoritative target, capability, effect, deny, expiry, and enabled state |
| `scan` | timeout, concurrency, user agent, redirect limit, rate limit, profile, proxy, headers, and legacy display scope |
| `auth` | web bearer, cookie, basic, or custom-header credentials |
| `tools` | external executable overrides |
| `ai` | optional provider adapter |
| `report` | artifact directory and evidence/remediation inclusion |
| `database` | connection URL, pool size, and migration behavior |
| `wordlists` | optional discovery and enumeration files |
| `hooks` | bounded local lifecycle processes |
| `audit_log` | local JSONL event sink |
| `cve` | disabled, mock, NVD, OSV, or composite lookup |
| `network_credentials` | SSH, SMB, SNMP, and Kerberos inputs |
| `cloud` | AWS, GCP, Azure, and Kubernetes credential hints |
| `webhooks` | compatibility-only shape; outbound delivery is disabled |

Secret-bearing structs use redacted `Debug` implementations. TOML serialization is not redaction and
must be protected like any other credentials file.

## Generated quick engagement

The generated shape is equivalent to:

```toml
[engagement]
name = "quick scan: owned.example"
enabled = true

[engagement.policy]
capabilities = ["dast-scan", "external-tool"]
effects = ["passive", "active-safe"]

[[engagement.policy.allowed_scope]]
kind = "exact"
value = "owned.example"

# One exact entry is also written for each DNS answer observed at init time.
[[engagement.policy.allowed_scope]]
kind = "exact"
value = "192.0.2.10"

[scan]
profile = "quick"
```

The real file also contains a generated UUID and every default section. A later DNS change is denied
until the operator regenerates or deliberately changes the engagement.

## AI

```toml
[ai]
enabled = true
provider = "codex"
# binary = "codex"
# model = "your-approved-model"
auto_analyze = false
```

`provider = "claude"` selects the compatibility adapter. `max_budget_usd` applies only to that
adapter. Legacy `claude_binary` remains readable but should not appear in new files.

## CVE providers

NVD and OSV are separate effect targets. Before either backend is constructed, the engagement must
allow its canonical provider URL and resolved addresses under `infra-scan/passive`, and allow the
existing cache directory through a `path_prefix` scope rule. The cache directory must already exist
so authorization cannot be used to create an arbitrary path.

## Adding a field

1. Add it to the narrow owning struct.
2. Define an explicit safe default.
3. Add serialization and compatibility tests.
4. Add redacted `Debug` behavior when it can carry a secret or credential-bearing URL.
5. If it enables an effect, add capability classification, authorization, audit, negative tests, and
   documentation before wiring the effect.
