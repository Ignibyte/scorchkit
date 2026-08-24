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
| DAST and recon | 89 | 67 application modules by default; 22 explicit compatibility modules |
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

## Install

ScorchKit supports Linux, macOS, and Windows. External tools are owned as Unix process groups on
Linux/macOS and kill-on-close Job Objects on Windows, with the same bounded descendant cleanup
contract on every supported host. Individual scanner binaries may have narrower platform support.

The repository also owns a reproducible release path for raw Linux x86-64, macOS x86-64/Arm64,
and Windows x86-64 binaries. It double-builds each native target with pinned Rust and production
features, then binds exact binary headers/digests, per-binary CycloneDX SBOMs, SLSA provenance,
checksums, and keyless Sigstore bundles before draft publication. See the
[release qualification and recovery guide](docs/guide/releases.md). No release workflow grants
target authorization or changes scanner effects.

Install `rustup`; the checkout selects its exact pinned Rust toolchain. Then build the smallest
binary that fits the workflow:

```bash
git clone https://github.com/Ignibyte/scorchkit.git
cd scorchkit
cargo build --locked --release
```

The core binary at `target/release/scorchkit` supports web, code, supply-chain, reporting, and local
AI-adapter commands. Build the supported production feature set when you also need infrastructure,
cloud compatibility, PostgreSQL-backed state, local/remote MCP, or the loopback control API:

```bash
cargo build --locked --release --features "infra cloud mcp control-api"
target/release/scorchkit --help
target/release/scorchkit doctor --deep
```

The `mcp` and `control-api` features include storage. PostgreSQL is required for projects, schedules, durable jobs,
and MCP persistence; direct scans do not need a database. `--all-features` is a repository-validation
mode, not the recommended operator build, because it also compiles quarantined native cloud SDK
modules that are not in the production registry.

### Optional scanner integrations

Built-in checks work without external scanners. Install only the integrations used by the selected
profile, then run `scorchkit doctor --deep` to verify executable paths and reviewed versions.

| Workflow | Common integrations | Version rule |
|---|---|---|
| Fast source analysis | Semgrep, Gitleaks, language-specific analyzers | Minimum or project-specific versions reported by `doctor` |
| Deep source analysis | CodeQL CLI bundle, Psalm, PHPStan | Complete local bundles or project-local tools; no scan-time downloads |
| Supply chain | OSV Scanner 2.3.8, Syft 1.50.0, Grype 0.116.1, Trivy 0.74.0 | Exact reviewed versions |
| Runtime application testing | OWASP ZAP 2.17.0, Nuclei 3.11.1, matching browser driver | Exact reviewed runtime plus required add-ons or signed local collection |
| Compatibility families | Network, enterprise, infrastructure, and cloud tools | Explicit selection and matching engagement grants |

See the [external tool checklist](docs/tools-checklist.md) for every supported binary and install
method. Installing a tool never adds it to an implicit application profile or grants permission to
run it.

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
| `pentest` | All 67 application modules, including `commix` | Explicit intrusive, external-tool, and exploit grants |

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

Nuclei execution is also explicit and local. ScorchKit accepts only a configured manifest of exact,
signed HTTP template bytes; classifies each template before authorization; and runs the pinned
Nuclei 3.11.1 executable without ambient templates, updates, credentials, protocols, or redirects.
Missing, rejected, failed, clean, and finding-producing runs remain distinct in every report. See
[the trusted Nuclei runtime contract](docs/tools/nuclei.md).

Common commands:

```bash
scorchkit doctor
scorchkit doctor --deep
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

Provider-neutral model roles are a separate disabled-by-default layer. `[model_analysis]` binds one
exact provider/model to each configured planning, finding-validation, correlation, attack-path,
remediation, or verification role. Host, service, and local adapters share one typed contract;
service calls add exact policy and credential-use authorization, no redirects, redaction,
no-retention declaration, and hard resource bounds. A role remains unavailable until its exact
binding passes all five built-in AppSec evaluation cases. Successful output is labeled with full
provider/model/role/location provenance and never becomes scanner evidence or execution authority.
See [model analysis](docs/architecture/model-analysis.md).

Canonical source-to-runtime correlation is deterministic and separate from AI. It links typed
finding-v2 identities into versioned application attack paths, requires source flow, redacted HTTP
proof, a shared weakness and precise application facet, and comparable deployment provenance before
using the `reproduced` state. Focused verification output is inert selector data; it never sends a
request or runs a test. Legacy title/module chains are compatibility-only and labeled unverified.
See [source/runtime correlation](docs/architecture/source-runtime-correlation.md).

Durable findings use an append-only validation and triage lifecycle. Human and deterministic system
transitions preserve the prior state, actor, reason, evidence references, time, and optional
same-finding model-analysis provenance without changing scanner output. Correlation decisions keep
every contributing finding/scanner/evidence identity, and suppressions are exact, project-scoped,
time-bounded visibility metadata rather than deletion. Fixed rediscovery becomes `regressed`;
materially changed proof returns the finding to `needs_context`. Control, CLI, MCP, and project
reports consume the same validated projection. See [finding triage](docs/architecture/finding-triage.md).

```bash
scorchkit run https://owned.example --profile quick --analyze
scorchkit analyze report.json --focus prioritize
```

## Codex plugin

The repository-owned package at `plugins/scorchkit` gives Codex six focused workflows for
engagement preparation, planning, execution, reporting, remediation verification, and tiered
application-security coordination. The coordinator combines Codex Security semantic change or
repository review with ScorchKit's deterministic MCP evidence while preserving separate
provenance. Operational skills stop when their required boundary is unavailable. They do not treat
a prompt, project, target registration, or plan as authorization and do not fall back to a
terminal-driven scan.

Codex model selection remains a host concern. Approved defenders can run the same workflows with
[Daybreak Blue](https://developers.openai.com/api/docs/models/daybreak-blue-latest), a frontier-model
alias calibrated for defensive cybersecurity work. Daybreak access requires separate approval and
provisioning for the applicable identity and product surface. ScorchKit does not grant access,
silently select a model, or promote Codex or Daybreak conclusions into scanner evidence.

The package stores no target, engagement, database URL, or credential. It is a host adapter over the
same agent-neutral engine and is not installed into a personal marketplace by the repository. See
[the Codex plugin guide](docs/guide/codex-plugin.md).

All 39 MCP tools advertise a versioned object output schema, complete safety annotations, and one
read, local-state, or external-effect class. Routed calls return native structured success/error
content; successful calls also retain the unchanged legacy text payload. Local stdio calls use the
local-process principal. The optional remote host derives `authenticated_bearer` subjects from
environment-backed credentials and binds them to the exact configured engagement. Self-asserted
client names remain untrusted trace context; ScorchKit engagement policy remains the sole target,
capability, and effect authorization source.

## Network and integration boundaries

- HTTP requests use one policy-bound client that checks the requested URL, every redirect,
  hostname, and every resolved IPv4 or IPv6 address before connection.
- Scheduled scans persist the exact engagement snapshot used at creation. A missing or changed
  snapshot denies execution.
- Project registration is inventory only. A project scan still requires a matching engagement.
- NVD and OSV backends require grants for their provider endpoint and existing cache directory.
- Native AWS, GCP, and Azure SDK modules remain outside the production registry until provider
  authentication and service requests use ScorchKit's policy-owned transport.
- External processes have bounded time and output and are owned as Unix process groups or Windows
  Job Objects so timeout, cancellation, error, success, and drop clean up descendants.
- Standard DAST and code runs can use versioned local lifecycle processors for preprocessing,
  immutable finding proposals, and reporting. Processor output may only narrow the policy-sealed
  run, never grants authority or replaces scanner evidence, and crosses reports/control/MCP/jobs as
  bounded redacted outcomes. Legacy hook arrays remain compatible through the same proposal model.
- Durable CLI and MCP job hosts can enqueue redacted lifecycle events in PostgreSQL and deliver
  them through the same policy-owned hostname, DNS-answer, connection, and redirect boundary.
  Delivery requires a separate `webhook-delivery`/`active-safe` grant and cannot change scan
  success. Authorization values are resolved from environment references only for claimed attempts.
- Authenticated remote MCP is opt-in through `scorchkit serve --remote`. Its supported profile is a
  loopback-only backend behind a same-host TLS reverse proxy with exact Host/Origin and HTTPS
  forwarding assertions, bounded requests/sessions, and bearer principal-to-engagement bindings.
  Direct TLS, public backend listeners, OAuth/OIDC, tenants, and RBAC remain unsupported.
- The provider-neutral control API is opt-in through `scorchkit control-api`. It requires an
  environment-backed bearer and exact engagement binding, accepts only a loopback bind and Host,
  and exposes bounded v1 description, command/query, and replayable SSE event routes. Remote or
  public control hosting is not supported.
- Finding triage mutations require `local-state`/`active-safe` grants for the exact canonical
  runtime, source, artifact, network, or cloud target before append-only storage changes. A project,
  model recommendation, or stored compatibility status is never sufficient authority.

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
- [Isolated WebAssembly extensions](docs/architecture/extensions.md)
- [Application supply-chain evidence](docs/architecture/application-supply-chain.md)
- [Agent integration](docs/architecture/agent.md)
- [Codex plugin](docs/guide/codex-plugin.md)
- [AI adapters](docs/architecture/ai.md)
- [Model analysis](docs/architecture/model-analysis.md)
- [Finding triage lifecycle](docs/architecture/finding-triage.md)
- [Module development](docs/architecture/modules.md)
- [External tool inventory](docs/tools-checklist.md)
- [Tutorials](docs/tutorials/README.md)

## License

MIT. See [LICENSE](LICENSE).
