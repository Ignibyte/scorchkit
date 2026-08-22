# Getting started

ScorchKit runs DAST, SAST, infrastructure, and cloud checks behind an explicit engagement policy.
Start with a system you own or have written permission to test. A project entry, prompt, or agent
approval does not authorize a scan.

## Install

The supported production hosts are Linux, macOS, and Windows. Install the current stable Rust
toolchain, then build the core CLI:

```bash
git clone https://github.com/Ignibyte/scorchkit.git
cd scorchkit
cargo build --locked --release
```

Use `target/release/scorchkit` directly or place it on your `PATH`. Build the supported production
feature set when you need infrastructure, cloud compatibility, PostgreSQL-backed state, or local
stdio MCP:

```bash
cargo build --locked --release --features "infra cloud mcp"
```

The `mcp` feature includes storage. Direct scans do not need PostgreSQL; projects, schedules, durable
jobs, and MCP persistence do. Do not use `--all-features` as an operator install shortcut: it also
compiles quarantined native cloud SDK modules that are test-only and absent from production
registries.

```bash
scorchkit --help
scorchkit doctor --deep
scorchkit modules --check-tools
```

Missing external scanners reduce the available tool-backed modules. Native DAST and infrastructure
checks remain usable. Install only the tools required for the selected workflow; several AppSec
integrations are exact-version contracts. The [external tool checklist](../tools-checklist.md) lists
every binary and current install rule, and individual tools may support fewer operating systems.
Cloud production scans currently use five external-tool adapters.

## Create a safe engagement

The safest first step is `init` with the exact target:

```bash
scorchkit init https://owned.example
```

Initialization parses the URL, performs one bounded DNS lookup, pins the hostname and current
addresses, and writes `scorchkit.toml`. It does not send an HTTP request. The generated policy grants
the quick profile only.

ScorchKit discovers configuration in this order:

1. explicit `--config <path>`;
2. `scorchkit.toml` in the current directory;
3. legacy `config.toml`;
4. in-memory defaults.

An explicit missing file is an error. Defaults contain no engagement, so effectful commands fail
closed.

Review the generated block before scanning:

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

# init also writes one exact rule for every DNS address it observed.
```

A later DNS change is denied until the policy is deliberately updated. Wildcards and CIDRs broaden
scope and should be added only when the authorization permits them.

## Run the first scan

```bash
scorchkit run https://owned.example --profile quick
```

The default run writes a JSON report under `./reports` and prints a terminal report. Override the
format globally:

```bash
scorchkit --output html run https://owned.example --profile quick
scorchkit --output sarif run https://owned.example --profile quick
scorchkit --output pdf run https://owned.example --profile quick
scorchkit --output terminal run https://owned.example --profile quick
```

Supported formats are terminal, JSON, HTML, SARIF, and PDF. `report.output_dir` controls the artifact
directory.

## Choose a DAST profile

| Profile | Modules | Required authorization |
|---|---|---|
| `quick` | small native discovery set | `DastScan/ActiveSafe` |
| `standard` | all built-in DAST modules | `DastScan/Intrusive` |
| `thorough` | built-ins and non-restricted tools | intrusive plus `ExternalTool` |
| `pentest` | credential and exploit adapters included | separate credential-test, credential-use, and exploit grants |

Installed tools do not expand the engagement. A broader profile fails before effects when its grants
are absent.

Useful DAST variants:

```bash
scorchkit recon https://owned.example
scorchkit scan https://owned.example
scorchkit run https://owned.example --modules headers,tech,ssl
scorchkit run https://owned.example --skip subdomain
scorchkit run https://owned.example --min-confidence 0.8
scorchkit run https://owned.example --template api
```

Proxy destinations are separate effect targets and must also be in engagement scope:

```bash
scorchkit run https://owned.example --profile quick --proxy http://127.0.0.1:8080
```

Use `--insecure` only for an authorized target whose certificate policy is intentionally relaxed.
It does not relax scope, redirect, or DNS-address authorization.

## Scan source code

Code scans require a canonical `path_prefix` grant plus `CodeScan/Passive` and `ExternalTool/Passive`.
The external-tool grant is required because the default SAST registry includes tool adapters.

```bash
scorchkit code ./src --profile quick
scorchkit code . --language rust --modules dep-audit,cargo_audit
scorchkit run https://owned.example --profile quick --code ./src
```

ScorchKit canonicalizes the path before policy comparison so a symlink cannot escape an allowed
root.

## Infrastructure and cloud scans

Infrastructure commands require the `infra` feature and `InfraScan/ActiveSafe` plus
`ExternalTool/ActiveSafe` for the exact host, endpoint, address, or CIDR.

```bash
scorchkit infra 127.0.0.1 --profile quick
scorchkit infra 192.0.2.0/28 --modules tcp_probe
```

Native DNS, TLS, and TCP paths authorize derived hostnames before DNS and every returned address
before connection. CIDR scans recheck each concrete address.

Cloud commands require the `cloud` feature. A cloud context requires `CloudScan`, `ExternalTool`, and
`CredentialUse` under the passive effect for the exact cloud target.

```bash
scorchkit cloud aws:123456789012 --profile quick
scorchkit cloud gcp:owned-project
scorchkit cloud azure:owned-subscription
scorchkit cloud k8s:owned-context
```

Cloud credentials can come from the standard provider environment and the `[cloud]` section. Keep
credential files and configuration permissions restricted. Native AWS, GCP, and Azure SDK modules
are test-only until their authentication and service transports enforce ScorchKit's network policy.

## Run a combined assessment

With the `infra` feature, `assess` runs any requested family concurrently and merges the results:

```bash
scorchkit assess \
  --url https://owned.example \
  --code ./src \
  --infra 127.0.0.1 \
  --profile quick
```

Add `--cloud` only when the cloud feature is enabled and its target has separate grants. Every
requested family is authorized independently before its context is constructed.

## Optional AI analysis

AI output is a labeled analysis layer. It does not modify scanner evidence or grant effects. Codex is
the default adapter:

```toml
[ai]
enabled = true
provider = "codex"
# binary = "codex"
# model = "your-approved-model"
auto_analyze = false
```

```bash
scorchkit run https://owned.example --profile quick --analyze
scorchkit run https://owned.example --profile quick --plan
scorchkit analyze reports/scan.json --focus prioritize
```

The Codex adapter uses non-interactive execution, no approval prompts, a read-only sandbox, an
ephemeral session, and prompt input over stdin. `provider = "claude"` selects the compatibility
adapter. If the configured provider is disabled or unavailable, deterministic scanning and reports
continue without AI output.

## Projects, schedules, and PostgreSQL

Stateless CLI scans do not require a database. Project persistence, schedules, and MCP use
PostgreSQL.

```bash
export DATABASE_URL='postgresql://USER@localhost/scorchkit'
scorchkit db migrate
scorchkit project create owned-app
scorchkit run https://owned.example --profile quick --project owned-app
scorchkit project show owned-app
```

Project registration is inventory, not authorization. The current engagement must still match the
registered canonical target. Schedules store the exact engagement snapshot used at creation and deny
execution when the snapshot is absent or differs from the active policy.

See [projects.md](projects.md) and `scorchkit schedule --help` for the storage workflows.

## Local MCP operation

Build with `mcp` and `storage`, configure PostgreSQL and an engagement, then start the stdio server:

```bash
scorchkit serve
```

The default remains local stdio. For authenticated remote operation, use a same-host TLS reverse
proxy and configure `[mcp.remote]` as shown in [the configuration architecture](../architecture/config.md).
Set each referenced token to a unique 32-byte-or-longer value, make its binding UUID equal the
enabled, unexpired configured engagement, then start the loopback backend explicitly:

```bash
export SCORCHKIT_MCP_OPERATOR_TOKEN='replace-with-a-unique-high-entropy-value'
scorchkit serve --remote
```

The proxy must terminate TLS, replace `X-Forwarded-Proto` with `https`, preserve the allowed public
Host, and forward bearer authentication to `/mcp`. Do not expose the cleartext backend, place it on
a different host, or add an unauthenticated wrapper. See [the MCP architecture](../architecture/mcp.md)
for all 39 tools, resources, prompts, identity rules, and authorization boundaries.

## CVE providers

The default CVE backend is disabled. NVD and OSV require separate passive infrastructure grants for
their provider URL and resolved addresses plus a `path_prefix` grant for an existing cache directory.
This prevents scan-target authorization from silently authorizing a third-party service or an
arbitrary filesystem path.

See [CVE backends](../architecture/cve-backends.md) for exact configuration.

## Hooks and webhooks

`[hooks]` entries are bounded local executables. Configured DAST hooks require `ExternalTool` for the
profile effect. Post-module hooks may replace a valid findings array. Pre-scan and post-scan output is
currently not applied.

PostgreSQL-backed `job run` and stateful MCP hosts can persist and deliver redacted lifecycle
webhooks. Configure `[[webhooks]]`, grant the destination and its addresses the separate
`webhook-delivery`/`active-safe` tuple, and use an environment-variable reference for any
`Authorization` value. `scorchkit webhook list`, `status`, `audit`, and `run-due` expose bounded
queue state. Delivery failures and retries never change the scan result; stateless MCP rejects
webhook-enabled configuration.

## Compare and resume

```bash
scorchkit diff reports/baseline.json reports/current.json
scorchkit run --resume reports/checkpoints/SCAN_ID.json
scorchkit completions zsh > _scorchkit
```

Checkpoint and report paths are based on `report.output_dir`.

## Troubleshooting

| Symptom | Check |
|---|---|
| `no engagement authorization is configured` | Run targeted `init` or supply a reviewed `[engagement]` block. |
| target is outside scope | Compare the normalized hostname, IP, CIDR, path, or cloud resource with `allowed_scope` and `denied_scope`. |
| hostname is allowed but DNS fails with a policy denial | Add only the specifically authorized returned addresses or CIDRs. |
| profile is denied | Add the exact capability/effect grants or select a narrower authorized profile. |
| tool is skipped | Run `scorchkit doctor --deep` and `scorchkit modules --check-tools`. |
| project, schedule, or MCP command cannot connect | Set a valid `DATABASE_URL`, migrate, and check PostgreSQL. |
| AI output is absent | Check `[ai] enabled`, provider binary, and `scorchkit doctor`; scan evidence is still valid. |

For the enforced boundary, read [SECURITY.md](../../SECURITY.md). For module IDs, read the
[module matrix](module-matrix.md). For repository development, read
[CONSTITUTION.md](../../CONSTITUTION.md), [AGENTS.md](../../AGENTS.md), and the
[roadmap](../planning/ROADMAP.md).
