# Module architecture

ScorchKit has four module families. They return the same `Finding` type and feed the same reporting
and storage surfaces, but each family receives a context sealed for its target and effects.

| Family | Trait | Context | Production registry |
|---|---|---|---:|
| DAST and reconnaissance | `ScanModule` | `ScanContext` | 91 |
| SAST | `CodeModule` | `CodeContext` | 22 |
| Infrastructure | `InfraModule` | `InfraContext` | 4, plus optional CVE correlation |
| Cloud | `CloudModule` | `CloudContext` | 5 |

`tests/module_census.rs` owns these counts. The cloud count excludes twelve private, test-only
provider SDK modules and the unregistered Pacu exploit module.

## Common contract

Each trait supplies stable module metadata and one asynchronous `run` method. The DAST shape is:

```rust,ignore
#[async_trait]
pub trait ScanModule: Send + Sync {
    fn name(&self) -> &str;
    fn id(&self) -> &str;
    fn category(&self) -> ModuleCategory;
    fn description(&self) -> &str;
    async fn run(&self, context: &ScanContext) -> Result<Vec<Finding>>;
    fn requires_external_tool(&self) -> bool { false }
    fn required_tool(&self) -> Option<&str> { None }
}
```

SAST adds language selection. Infrastructure and cloud use family-specific categories and target
metadata. Their concrete definitions under `src/engine` are authoritative.

An empty finding vector means the module completed and observed no issue. An error means it could not
complete its contract. A denial, timeout, unavailable program, or malformed response must remain an
error or an explicit skipped-module outcome. It is not a clean security result.

## Context ownership

Production contexts come from `facade::Engine`. Their constructors are internal so callers cannot
pair an unverified target with an arbitrary client, resolver, executor, credential set, or path.

Context effect seams include:

- `ScanContext::http_client()` for policy-bound HTTP;
- `ScanContext::run_tool` and `CodeContext::run_tool` for bounded external programs;
- the private `PolicyNetwork` in DAST and infrastructure contexts for DNS, TCP, and TLS;
- a canonical authorized root in `CodeContext`;
- credential and external-tool authorization in `CloudContext`.

A module must use those seams. If a required effect has no context-owned operation, extend the engine
boundary with policy, audit, bounds, and tests before adding the module. Do not construct a raw HTTP
client, resolver, socket, subprocess, credential loader, or effectful path inside the module.

## Registries and profiles

Each family has one `register_modules()` function. An orchestrator loads that registry, then applies
profile, category, include, and exclude filters. Installed tools affect availability, not
authorization. The facade validates the profile's capability and effect requirements before it
creates the context.

Trusted callers can add a Rust module with the orchestrator's `add_module` method. Calling
`register_default_modules()` first runs the extension alongside the built-in registry. The public
example and security constraints are in [the Rust module extension API](../plugin-sdk.md).

TOML DAST plugins describe bounded external commands. They still run through the context executor,
including target and `ExternalTool` authorization, executable resolution, timeout, output limit,
exit policy, and process-tree cleanup. They are trusted configuration, not a sandbox.

## External-tool modules

One-shot tool modules declare a `ToolInvocation` and call a context-owned executor. The registry-wide
contract test checks the declared program, arguments, timeout, output cap, exit behavior, and parser
result for all 45 DAST and 21 SAST wrappers.

Interactsh is deliberately separate because it owns a long-lived callback session. It still uses the
shared process-group owner, bounded reader, and cleanup behavior for stop, failure, timeout, overflow,
and drop.

Cloud production modules are the five bounded wrappers. Native AWS, GCP, and Azure implementations
remain private and test-only until provider authentication and service requests use a policy-owned
transport.

## Findings and evidence

The module ID on a `Finding` must match `id()`. Use severity for impact and confidence for evidence
strength. Attach the actual observation, a specific remediation, and OWASP or CWE mappings only when
the mapping is supported.

Keep raw scanner observations intact. Terminal encoding changes presentation only. Agent analysis is
a separate labeled layer and never replaces evidence or changes a scanner result.

## Tests

A module change normally needs:

- metadata and registry coverage;
- clean and positive fixtures;
- malformed and boundary inputs for parsers;
- a loopback integration test for network behavior;
- explicit denial tests for every new target or effect path;
- executor-contract coverage for an external tool;
- profile-selection and report mapping when behavior changes across public surfaces.

Run repository Cargo checks sequentially. The normal final delivery verdict is
`bash bin/gate.sh --diff`, not a hand-selected subset of tests. The focused-repair exception is
limited by `CONSTITUTION.md` §19 and does not change module-level test requirements.

See [the extension tutorial](../tutorials/06-extending-with-custom-modules.md), [SAST](sast.md),
[infrastructure](infra.md), and [cloud](cloud.md) for family details.
