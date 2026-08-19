# Cargo workspace boundaries

ScorchKit is a Cargo workspace with 13 internal library packages and one root composition package.
The root `scorchkit` package remains the public library and binary. Existing `scorchkit::...` paths
are compatibility re-exports of package-owned types where a stable contract has moved.

## Package ownership

| Package | Owns | Does not own |
|---|---|---|
| `scorchkit-policy` | engagement, scope, capability, effect, and decision types | clients, contexts, or effect execution |
| `scorchkit-core` | targets, findings, evidence, results, events, correlation, CVE, compliance, and scanner-adapter contracts | CLI, MCP, storage, or agent adapters |
| `scorchkit-config` | application configuration, credentials, CVE configuration, and webhook shape | effect authorization or webhook delivery |
| `scorchkit-executor` | bounded scheduling plus durable job and store contracts | family orchestration or PostgreSQL queries |
| `scorchkit-tools` | bounded subprocess invocation, output, cancellation, and process ownership | scanner-specific argument construction |
| `scorchkit-web` | DAST/recon category and descriptor vocabulary | contexts, registries, or concrete scanners |
| `scorchkit-code` | SAST category and descriptor vocabulary | code-path authorization or concrete scanners |
| `scorchkit-infra` | infrastructure category and descriptor vocabulary | network contexts or probes |
| `scorchkit-cloud` | cloud category and descriptor vocabulary | credentials, contexts, or provider calls |
| `scorchkit-storage` | stable persistence record models | database connection, queries, or migrations |
| `scorchkit-mcp` | input schemas, server instructions, tool inventory, annotations, and result envelope | transport state or tool business logic |
| `scorchkit-cli` | argument parser, feature-aware commands, and completion generation | command execution or terminal rendering |
| `scorchkit-agent` | host hints, manifest, prompt, and typed reasoning payloads | provider process execution or scan authority |
| `scorchkit` | policy-sealed contexts, registries, concrete adapters, facade, CLI/MCP handlers, storage adapters, and reports | duplicate ownership of extracted contracts |

Family packages intentionally own only stable vocabulary in this extraction. Moving their contexts
would require making crate-private constructors public or redesigning the authorization proof.
Concrete scanners and their policy-sealed contexts therefore remain in `scorchkit` until a later
ticket can move them without widening construction authority.

## Allowed dependency direction

An arrow means the package on the left depends on the package on the right.

```mermaid
flowchart LR
    ROOT["scorchkit composition"] --> POLICY["scorchkit-policy"]
    ROOT --> CORE["scorchkit-core"]
    ROOT --> CONFIG["scorchkit-config"]
    ROOT --> EXECUTOR["scorchkit-executor"]
    ROOT --> TOOLS["scorchkit-tools"]
    ROOT --> LEAVES["family, storage, MCP, CLI, and agent packages"]
    CORE --> POLICY
    CONFIG --> CORE
    CONFIG --> POLICY
    EXECUTOR --> CONFIG
    EXECUTOR --> CORE
    EXECUTOR --> POLICY
    TOOLS --> CORE
    LEAVES --> CORE
```

The four scanner-family packages depend on `scorchkit-core` for the common adapter descriptor.
Storage, MCP, CLI, and agent packages remain independent leaves. No lower package may depend on the
root `scorchkit` package. Exact allowed edges are enforced in `tests/workspace_architecture.rs`.

## Compatibility and features

The root facade preserves existing import paths and type identity. For example,
`scorchkit::Finding` and `scorchkit_core::Finding` are the same Rust type. The same rule applies to
policy, configuration, scheduler, job, process, family-category, storage, MCP, CLI, and agent
contracts covered by the architecture test.

Root feature names and defaults remain unchanged. The root forwards `storage`, `mcp`, `infra`, and
`cloud` only to packages that need those parser or configuration variants. Package extraction does
not authorize a target or enable a stronger effect class.

## Workspace quality contract

The canonical gate runs formatting, Clippy, tests, Rustdoc, coverage, Nextest, Semgrep, source bans,
and mutation inventory across the workspace. Direct development checks should also use
`--workspace` when the command supports it. PostgreSQL and CLI/MCP integration lanes remain rooted
in the `scorchkit` package because they exercise the composed application.
