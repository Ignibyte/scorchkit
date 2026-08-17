# Development guide

ScorchKit is an agent-neutral security execution engine. Product changes preserve a strict split:
the engine owns authorization, effects, findings, and evidence; hosts such as Codex provide planning
and interpretation around those controls.

Read `CONSTITUTION.md`, `AGENTS.md`, `SECURITY.md`, and `docs/planning/ROADMAP.md` before changing code
or scan behavior.

## Use the repository pipeline

All implementation work follows one versioned workflow:

```text
create → plan → design → implement → inspect → validate → complete → delivery
```

Start by checking the current state:

```bash
bash bin/pipeline.sh doctor
bash bin/pipeline.sh status
```

Resume the active ticket when one exists. Do not create a second active spec and notes pair. Use
`bash bin/pipeline.sh` for transitions instead of editing phase state or moving artifacts manually.

Plan and design use observable EARS requirements. Inspect records correctness, security, data
integrity, and simplification findings with a disposition. Validate requires a green
`bash bin/gate.sh --diff`. A ticket can use `--focused-repair` only under the explicit, executable
conditions in `CONSTITUTION.md` §19. Completion submits the AAR and archives the ticket through the
script. Archival changes the worktree, so delivery reruns the same approved gate and checks the
receipt.

Codex uses `.agents/skills/scorchkit-pipeline` as an adapter to this workflow. Other agents and humans
use the same scripts and repository state.

## Source layout

```text
src/
  engine/       targets, policy, contexts, findings, evidence, events
  facade.rs     public construction and authorization boundary
  recon/        native DAST reconnaissance modules
  scanner/      native DAST vulnerability modules
  tools/        DAST external-tool adapters
  sast/         native code analysis
  sast_tools/   SAST external-tool adapters
  infra/        TCP, TLS, DNS, nmap, and CVE correlation
  cloud/        bounded cloud adapters and quarantined provider code
  runner/       family orchestration and process ownership
  cli/          command definitions and terminal presentation
  mcp/          local stdio agent surface
  storage/      PostgreSQL persistence
  report/       terminal, JSON, HTML, SARIF, and PDF output
  agent/        provider-neutral host contracts
  ai/           provider-neutral planning and analysis adapters
```

The current layout is a single crate. The ordered crate extraction is documented in the roadmap and
starts only after policy, job, executor, and provider contracts are stable.

## Preserve the effect boundary

Every public path that can create network, filesystem, cloud, credential, or subprocess effects
requires an `Engagement` decision for the canonical target, capability, and effect class before the
resource is created.

- Build production contexts through `facade::Engine`.
- Use `ScanContext::http_client()` for target HTTP.
- Use context-owned tool execution for external programs.
- Keep code traversal under the canonical authorized `CodeContext::path`.
- Use `PolicyNetwork` for native DNS, TCP, and TLS inside the crate.
- Authorize provider endpoints and cache paths separately from scan targets.
- Keep native cloud SDK modules out of production until their authentication and service transports
  enforce the same boundary.

Prompts, project registration, config target lists, and agent approval are context. They do not grant
effects. See `SECURITY.md` for the enforced support boundary.

## Add or change a module

Choose the family whose context owns the required effect. Add the implementation to its registry and
update `tests/module_census.rs` when the production count changes. Trusted out-of-tree DAST and SAST
examples live under `examples/custom_scanner` and `examples/custom_code_scanner`.

The detailed contracts are in:

- [module architecture](../architecture/modules.md);
- [Rust module extension API](../plugin-sdk.md);
- [custom module tutorial](../tutorials/06-extending-with-custom-modules.md);
- [CVE backend tutorial](../tutorials/07-extending-cve-backends.md).

For an external program, define one bounded invocation and parse its output separately. Do not call
`std::process`, `tokio::process`, or a raw runner from a module. The shared executor owns executable
resolution, timeout, output caps, exit policy, process-tree cleanup, and authorization.

## Test behavior, not implementation shape

Tests should observe the contract that would break if the code were removed or inverted. Useful
layers are:

- pure parser and mapping fixtures;
- policy denial and authorized-control tests;
- loopback network tests with explicit scope;
- injected process execution contracts;
- profile and registry selection tests;
- report, CLI, MCP, storage, and schedule integration tests when those surfaces change;
- mutation tests at shared seams after normal tests pass.

Do not use external targets in the automated suite. A timeout against a remote address is not a
passing test. Database-backed delivery uses a migrated disposable PostgreSQL database through
`DATABASE_URL`.

Reasoned live-network smoke tests may remain ignored during normal execution. Do not add a silent
skip, retry, baseline, suppression, or broad exclusion to obtain green.

## Quality commands

Use the canonical scripts because they include feature-state, dependency, security, formatting,
coverage, mutation, database, CLI, and MCP contracts that a short Cargo command does not cover:

```bash
bash bin/gate.sh --fast
bash bin/mutants.sh --inspect
DATABASE_URL=postgresql://USER@localhost/DATABASE bash bin/gate.sh --diff
```

The release baseline also requires a complete `bash bin/gate.sh --full`. Cargo commands run
sequentially. The mutation runner alone manages its bounded workers and local scratch directories.

`bin/gate.sh` is the only delivery verdict. Its baked floors cannot be lowered by an environment
override. A green DIFF, FULL, or amendment-qualified FOCUSED-REPAIR gate writes a receipt tied to the
exact worktree. Focused evidence is also bound by digest. Any content edit makes the receipt stale.

## Code conventions

- Deny unsafe code and return typed errors for malformed or operator-controlled input.
- Document public items and modules.
- Keep domain, policy, findings, evidence, and execution independent of CLI, MCP, storage, and agent
  providers.
- Keep terminal output out of library execution paths. Publish structured events and render them at
  the CLI boundary.
- Preserve scanner evidence and label agent-generated analysis separately.
- Justify a narrow lint suppression next to the item. Do not add crate-wide or lint-group allows.
- Keep actionable marker comments in planning documents, not source code or guides.

## Documentation and completion

Update the architecture or guide that owns the changed public behavior. Avoid copying large source
snippets into several documents because they drift. Link to a single canonical example and make
advertised extension crates compile in isolation.

Before completion, record exact commands and outcomes in the active notes, submit the AAR, update
the knowledge register with reusable lessons, and update `CHANGELOG.md`. Let the pipeline script
archive the artifacts. Rerun the DIFF gate after archival and verify `bash bin/pipeline.sh receipt`
before a commit or pull request.
