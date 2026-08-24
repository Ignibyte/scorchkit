# Typed run processors and legacy lifecycle hooks

ScorchKit's run pipeline is a versioned, provider-neutral contract. Configured local processors
receive one typed JSON request on standard input and return one typed proposal on standard output.
The engine validates the contract and response, clamps proposals to the policy-sealed run ceiling,
and stores a separate processor outcome. A processor never receives an engagement, store, network
client, or executable handle and never replaces scanner evidence.

Local execution uses the shared bounded process owner and therefore still requires the host's
`ExternalTool` authorization. Processor declarations and output are context, not grants.

## Hook points

| Phase / compatibility setting | Runs | Typed input | Accepted proposal |
|---|---|---|---|
| `preprocessing` / `pre_scan` | before modules start | authorized target, runnable IDs, capabilities, maximum effect, credential-use flag | an equal target plus a subset of modules/capabilities and no-higher effect/credential use |
| `enrichment` / `post_module` | after each successful module | immutable finding identities and bounded snapshots | retain, filter, duplicate, enrich, or correlate dispositions keyed to source identities |
| `reporting` / `post_scan` | after findings are collected | scan identity, target, count, and five severity counts | bounded redacted annotations |

Processors at one phase run sequentially by `(order, id)`. An accepted preprocessing proposal
becomes the ceiling and input for the next processor. Empty output is a passthrough. Every explicit
response must repeat the registered processor identity and phase under
`scorchkit.run-processor-response/v1`.

## Configuration

```toml
[hooks]
timeout_seconds = 30
fail_open = false

[[hooks.processors]]
schema = "scorchkit.run-processor/v1"
id = "select.modules"
path = "/opt/scorchkit/processors/select-modules"
phase = "preprocessing"
input_schema = "scorchkit.run-preprocess-input/v1"
output_schema = "scorchkit.run-preprocess-proposal/v1"
capabilities = ["dast-scan", "external-tool"]
failure_mode = "required"
order = 10

[hooks.processors.budget]
timeout_millis = 1000
max_input_bytes = 65536
max_output_bytes = 65536
```

Each explicit processor requires its complete version, identity, phase/schema pair, capability set,
failure mode, deterministic order, and nonzero bounded budgets. `required` failures abort the scan;
`optional` failures record a redacted `degraded` outcome and continue without a proposal.

The original `pre_scan`, `post_module`, and `post_scan` arrays remain readable. They run after
explicit processors in stable list order under reserved `legacy.*` identities. Their global
`timeout_seconds` and `fail_open` settings map to typed budgets and required/optional behavior.
Legacy pre-scan output may narrow modules, legacy finding arrays become retain/filter proposals,
and non-empty legacy post-scan output records only a completion annotation. Arbitrary legacy JSON
cannot add authority or delete or modify scanner findings.

## Process controls

Each invocation has an exact input ceiling, output-stream ceiling, and wall-time budget; canonical
executable resolution; no shell interpolation; and whole-tree cleanup through a Unix process group
or Windows Job Object. Inputs, responses, proposals, annotations, diagnostics, and result outcome
collections also have protocol bounds. Public and durable boundaries revalidate outcomes and redact
diagnostics. Processor output remains untrusted until all checks succeed.

## Webhooks

Webhooks are output-only durable notifications and do not run as local notification processors.
DAST awaits durable publication of each typed processor outcome before best-effort broadcast.
Durable CLI and MCP job hosts redact matching events before enqueueing them in PostgreSQL. Records hold a stable
destination ID and an engagement snapshot but never the configured URL or authorization value.

The delivery worker uses revision compare-and-swap, a bounded ownership lease, recovery, batches,
timeouts, redirects, exponential backoff, and a terminal `succeeded` or `exhausted` state. Every
attempt uses `Capability::WebhookDelivery` and `EffectClass::ActiveSafe` through the shared
engagement-bound client, including hostname, every DNS answer, connection, and redirect checks.
Remote response bodies are never read or persisted. Enqueue and delivery faults remain visible in
queue and audit state but cannot replace a scan result.

Delivery is at-least-once across a worker crash after remote acceptance but before terminal commit.
Every request includes stable `X-ScorchKit-Delivery-Id` and one-based
`X-ScorchKit-Delivery-Attempt` headers so receivers can enforce idempotency.

CLI operators can use `scorchkit webhook list`, `status`, `audit`, and `run-due`. Stateful MCP runs
the same recovery and delivery pass in the background; webhook-enabled stateless MCP startup fails.
