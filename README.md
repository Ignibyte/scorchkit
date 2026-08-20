# ScorchKit

ScorchKit is an agent-neutral application-security testing engine written in Rust. It runs
deterministic SAST, SCA, secret, artifact, web, and API checks behind one engagement policy, then
preserves findings and evidence for an agent or human to analyze. Codex is the preferred agent host.
The scanning core does not depend on an agent vendor, and a Claude CLI compatibility adapter remains
available. General network, enterprise, and cloud-account scanners are explicit compatibility
features rather than default product selections.

ScorchKit is a testing tool, not an authorization system. Only scan systems you own or have explicit
permission to test. A project target, prompt, or agent approval does not replace an engagement grant.

## Current capability census

| Family | Registered modules | Notes |
|---|---:|---|
| DAST and recon | 90 | 68 application modules by default; 22 explicit compatibility modules |
| SAST | 22 | 21 application modules by default; ScoutSuite is explicit cloud-account compatibility |
| Infrastructure | Up to 5 | Explicit compatibility family: 4 core probes plus optional CVE correlation |
| Cloud | 5 | Explicit compatibility family of bounded tool adapters; native provider SDK modules remain quarantined |
| Maximum | 122 | All production registries, including optional CVE correlation |

The [application-security catalog](docs/architecture/application-security-catalog.md) explains the
default and compatibility split. The source registries remain authoritative for the complete
inventory.

## Workspace architecture

The root `scorchkit` package is the public library, binary, and composition layer. Thirteen internal
packages under `crates/` own stable policy, domain, configuration, execution, subprocess, family,
storage-model, MCP, CLI, and agent contracts. Existing `scorchkit::...` imports remain compatible,
and lower packages cannot depend on the root composition package. See the
[workspace boundary](docs/architecture/workspace.md).

## Supported hosts

ScorchKit currently supports Unix process semantics on Linux and macOS. Windows builds are rejected
until the external-process owner has a Windows Job Object backend with the same descendant cleanup
guarantees.

## Build

```bash
git clone https://github.com/chadpeppers/scorchkit.git
cd scorchkit
cargo build --release --all-features
```

The binary is `target/release/scorchkit`. PostgreSQL is required for project, schedule, and MCP
persistence features. Direct stateless scans do not need a database.

## Safe first scan

`init <target>` validates the URL, performs a bounded DNS lookup, pins the current addresses, and
writes `scorchkit.toml` with a quick-profile engagement. It sends no HTTP request to the target.
ScorchKit discovers `scorchkit.toml` automatically before the legacy `config.toml` name.

```bash
scorchkit init https://owned.example
scorchkit run https://owned.example --profile quick
```

Without `[engagement]`, every scan family fails closed before creating its effectful resources.
Running `scorchkit init` without a target still writes a default `config.toml`, but that file contains
no authorization and cannot start a scan until an engagement is added.

## Profiles and grants

| Profile | Selection | Required effect |
|---|---|---|
| `quick` | `headers`, `tech`, `ssl`, `misconfig` | `active-safe` |
| `standard` | Built-in application DAST modules | `intrusive` |
| `thorough` | Application modules except credential-test and exploit effects | `intrusive` plus `external-tool` capability |
| `pentest` | All 68 application modules, including `commix` | Explicit intrusive, external-tool, and exploit grants |

Broader profiles are never inferred from installed tools. Expand the engagement deliberately and
review the resulting scope before using them.

Code scans use the same profile names with code-specific selection:

| Code profile | Selection |
|---|---|
| `quick` | Secret and source-dependency analysis |
| `standard` | Fast application source, correctness, secret, dependency, IaC, and artifact modules |
| `thorough` | Standard modules plus CodeQL and Psalm where their languages apply |
| `pentest` | The same deep code selection; runtime effects remain separately authorized |

CodeQL supports JavaScript/TypeScript, Python, and Ruby in no-build mode. Psalm supplies PHP taint
analysis. Unsupported languages, missing tools, successful runs, and failures remain distinct in
the returned module outcomes. Semgrep uses an embedded digest-identified rule pack and never selects
`--config auto`.

Application supply-chain work is an ordered offline pipeline rather than three independent scanner
modules. Quick scans run OSV Scanner against declared source lockfiles. Standard adds one exact
CycloneDX 1.6 SBOM from Syft and Grype analysis of those same bytes. Thorough and pentest add Trivy
as a second consumer of the same SBOM. Missing tools or provider snapshots make coverage incomplete;
attempted producer, consumer, or parser failures make it degraded.

The cache root must already exist with owner-only permissions and be separately authorized as local
state. Scans cannot refresh databases, pull registry images, use a container daemon, run target
builds or package managers, or inherit ambient credentials. Provider refresh is a separate explicit
operation. See [application supply-chain evidence](docs/architecture/application-supply-chain.md).

Common commands:

```bash
scorchkit doctor
scorchkit modules --check-tools
scorchkit modules --include-compatibility
scorchkit code ./src --profile standard
scorchkit code ./src --profile thorough
scorchkit supply-chain scan ./src --kind source-directory --profile standard
scorchkit supply-chain cache-status
scorchkit infra 192.0.2.10
scorchkit assess --url https://owned.example --code ./src --infra 192.0.2.10
scorchkit diff baseline.json current.json
```

Feature-specific commands require the corresponding Cargo feature. Run `scorchkit --help` for the
compiled binary's exact command surface.

## AI analysis

AI is optional and separate from scanner evidence. If the configured host is unavailable,
deterministic scanning and reporting continue without it. Codex is the default adapter:

```toml
[ai]
enabled = true
provider = "codex"
# binary = "codex"
# model = "your-approved-model"
auto_analyze = false
```

The Codex adapter runs non-interactively with no approval prompts, a read-only sandbox, an ephemeral
session, and prompts on standard input. Set `provider = "claude"` for the compatibility adapter.
Legacy `claude_binary` configuration is still read and selects that adapter, but new configuration
should use `provider` and `binary`.

Planning, analysis, correlation, and remediation use the same typed `scorchkit.ai/v1` request and
response contract for both adapters. Invalid or mismatched provider output is rejected. AI failure
does not alter deterministic scan evidence, rule-based correlation, or local remediation guidance.

```bash
scorchkit run https://owned.example --profile quick --analyze
scorchkit analyze report.json --focus prioritize
```

## Codex plugin

The repository-owned package at `plugins/scorchkit` gives Codex five focused MCP workflows for
engagement preparation, planning, execution, reporting, and remediation verification. Operational
skills use the local stdio MCP server directly and stop when it is unavailable. They do not treat a
prompt, project, target registration, or plan as authorization and do not fall back to a
terminal-driven scan.

The package stores no target, engagement, database URL, or credential. It is a host adapter over the
same agent-neutral engine and is not installed into a personal marketplace by the repository. See
[the Codex plugin guide](docs/guide/codex-plugin.md).

All 33 MCP tools advertise a versioned object output schema, complete safety annotations, and one
read, local-state, or external-effect class. Routed calls return native structured success/error
content; successful calls also retain the unchanged legacy text payload. The local-process principal
and self-asserted client name are trace context only; ScorchKit engagement policy remains the sole
authorization source.

## Network and integration boundaries

- HTTP requests use one policy-bound client that checks the requested URL, every redirect,
  hostname, and every resolved IPv4 or IPv6 address before connection.
- Scheduled scans persist the exact engagement snapshot used at creation. A missing or changed
  snapshot denies execution.
- Project registration is inventory only. A project scan still requires a matching engagement.
- NVD and OSV backends require grants for their provider endpoint and existing cache directory.
- Native AWS, GCP, and Azure SDK modules remain outside the production registry until provider
  authentication and service requests use ScorchKit's policy-owned transport.
- External processes have bounded time and output and are owned as Unix process groups so timeout,
  cancellation, error, and drop clean up descendants.
- Webhook configuration is accepted for file compatibility, but outbound webhook delivery is
  disabled until it can use the same policy-owned network boundary.
- Remote MCP transport is not supported. The current server uses local stdio transport.

See [SECURITY.md](SECURITY.md) for the enforced boundary and current limitations.

## Development workflow

Repository changes use a spec-driven, agent-neutral pipeline:

```text
create → plan → design → implement → inspect → validate → complete → delivery
```

`bin/pipeline.sh` owns phase state. `bin/gate.sh` owns the delivery verdict. A green DIFF or FULL
gate writes a receipt bound to the exact worktree, and the Git hook rejects missing or stale
receipts. Codex discovers the repository adapter at `.agents/skills/scorchkit-pipeline`; other agents
and humans use the same scripts and files.

```bash
bash bin/pipeline.sh doctor
bash bin/pipeline.sh status
bash bin/gate.sh --fast
bash bin/gate.sh --diff
```

Read [CONSTITUTION.md](CONSTITUTION.md), [AGENTS.md](AGENTS.md), and the
[roadmap](docs/planning/ROADMAP.md) before changing code or scan behavior.

## Documentation

- [Getting started](docs/guide/getting-started.md)
- [Architecture overview](docs/architecture/overview.md)
- [Cargo workspace boundaries](docs/architecture/workspace.md)
- [Application-security adapter catalog](docs/architecture/application-security-catalog.md)
- [Application supply-chain evidence](docs/architecture/application-supply-chain.md)
- [Agent integration](docs/architecture/agent.md)
- [Codex plugin](docs/guide/codex-plugin.md)
- [AI adapters](docs/architecture/ai.md)
- [Module development](docs/architecture/modules.md)
- [External tool inventory](docs/tools-checklist.md)
- [Tutorials](docs/tutorials/README.md)

## License

MIT. See [LICENSE](LICENSE).
