# CLI

The Clap-based CLI is a host adapter around the same `Engine`, orchestrators, storage, reports, and
AI providers used by MCP and library consumers. It does not have a scope bypass.

## Startup flow

1. Parse global options and the selected command.
2. Load explicit config or discover `scorchkit.toml` then `config.toml`.
3. Apply narrow CLI overrides such as output, proxy, and timeout.
4. Construct `Engine::new(config)` for any effectful operation.
5. Normalize the target and profile and require the engagement decision.
6. Create the sealed family context and run the selected orchestrator.
7. preserve structured evidence, save requested artifacts, and escape untrusted terminal text.

Missing engagement or insufficient scope/capability/effect returns an error before the scan resource
is created.

## Command families

| Area | Commands |
|---|---|
| DAST | `run`, `recon`, `scan`, `dast`, `modules`, `doctor` |
| SAST | `code` |
| Combined | `assess` |
| Infrastructure/cloud | `infra`, `cloud` when compiled |
| Analysis/reporting | `analyze`, `diff` |
| Agent host | `agent`, `serve` when compiled |
| Persistence | `db`, `project`, `finding`, `schedule`, `job` when compiled |
| Setup | `init`, `completions` |

Run `scorchkit --help` and `scorchkit <command> --help` for the exact surface of the compiled feature
set.

## Safe start

```bash
scorchkit init https://owned.example
scorchkit run https://owned.example --profile quick
```

`init <target>` resolves and pins addresses but sends no HTTP request. It writes `scorchkit.toml`,
which the next command discovers automatically.

## Profiles

| Profile | Modules | Required effect |
|---|---|---|
| `quick` | headers, tech, SSL, misconfiguration | active-safe |
| `standard` | built-in application modules | intrusive |
| `thorough` | application modules except credential-test and exploit effects | intrusive and external-tool capability |
| `pentest` | all 67 application modules | explicit exploit grants in addition to intrusive and external-tool capability |

Unknown profiles are errors. `commix` is restricted to `pentest`. Network, enterprise credential,
and cloud-account adapters remain outside every implicit profile; explicit module IDs or the
`compatibility` template make them eligible without granting their required effects.

`dast <request.json>` is the dedicated authenticated application-assessment path. The bounded JSON
request names an authorized target, a `passive`, `standard`, or `active` phase profile, configured
persona IDs, and digest-pinned local OpenAPI or GraphQL schemas. It invokes the same policy-sealed
service as MCP and `Engine::application_dast`; it does not accept arbitrary ZAP plans or secrets.

## Output

The CLI supports terminal, JSON, HTML, SARIF, and PDF output. Structured formats retain raw evidence.
Terminal and human-log sinks neutralize control characters and bidirectional overrides. Secrets in
configuration diagnostics are redacted.

## Storage and schedules

Project and schedule commands require PostgreSQL. Project registration does not authorize a target.
A schedule can be created only for a registered target under the current engagement, and its exact
engagement snapshot is stored. Due execution claims rows in a short transaction, advances the
occurrence, releases the database connection, and then runs effects.

Durable DAST jobs use `job run`, `list`, `status`, `cancel`, `recover`, and `resume`. Run and resume
stay in the foreground so Ctrl-C becomes a stored cancellation instead of abandoning an unowned
task. Recovery marks expired nonterminal attempts interrupted; resume reauthorizes and creates a
linked attempt containing only safely completed evidence.

## AI

`--analyze`, `analyze`, planning, and `agent` use the configured provider. Codex is the default; Claude
is a compatibility adapter. Provider failure is non-fatal to deterministic scans and never changes
scanner evidence.

## Source layout

```text
src/cli/
  args.rs       Clap commands and value enums
  runner.rs     dispatch and family composition
  init.rs       fail-closed engagement bootstrap
  doctor.rs     external tool inventory and health checks
  project.rs    project and target operations
  finding.rs    finding lifecycle
  schedule.rs   schedule creation and due execution
  job.rs        durable DAST job lifecycle
  serve.rs      local stdio MCP startup
```
