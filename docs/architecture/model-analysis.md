# Model analysis

ScorchKit has a provider-neutral model-analysis boundary for planning, finding validation,
correlation, attack-path reasoning, remediation, and verification. It is disabled by default and is
separate from the legacy `scorchkit.ai/v1` compatibility adapters.

Model output is interpretation. It cannot create scanner evidence, authorize an effect, modify an
engagement, or transition a finding. A successful production response becomes a labeled
`scorchkit.model-analysis/v1` child record with complete provenance. An independently authorized
triage transition may cite the identity of a model-analysis child belonging to the same finding,
but the human or deterministic system actor remains the transition authority and disagreement is
preserved in the append-only history.

## Exact role resolution

Each role has at most one configured provider and exact model. Resolution never searches a
preference list or substitutes a different model. Readiness is a closed state:

| State | Meaning |
|---|---|
| `disabled` | The complete model-analysis feature is disabled. |
| `unconfigured` | The requested role has no binding. |
| `invalid` | Configuration is malformed or contains an ambiguous binding/evaluation. |
| `unavailable` | The exact process or environment-backed service credential is unavailable. |
| `evaluation_required` | The exact provider/model/role/contract/corpus key has not passed every case. |
| `ready` | Configuration, availability, and the exact evaluation evidence are valid. |

`ControlQueryV1::GetModelReadiness` returns all six roles without starting a process or request. Its
projection includes only role, provider, model, execution ownership, state, and a stable reason;
binary paths, endpoints, environment-variable names, and credentials are absent.

## Contracts and provenance

All adapters consume and return `scorchkit.model-analysis/v1`. The consumer revalidates the schema,
provider, exact model, role, payload kind, evidence-digest set, confidence bound, canonical
redaction, and deterministic ordering. Evaluation requests are also pinned to the built-in corpus
case identity, class, prompt, and version.

Production provenance records:

- provider and exact model;
- role and execution location;
- request contract and calling workflow versions;
- every input evidence SHA-256 digest;
- trusted completion time and model-reported confidence.

The record is appended under `FindingRecordV2.agent_analysis`. Finding identity and scanner
evidence do not include this layer. PostgreSQL reads independently validate every stored analysis
child against its raw canonical document and duplicated schema, identity, parent, and timestamp
columns before control or MCP projection. HTML, terminal, PDF, and SARIF reports retain the same
provider/model/role/location label.

## Adapters

| Adapter | Ownership and controls |
|---|---|
| `host_managed` | A contract-compatible host process, bounded to five minutes and 8 MiB. It requires `external-tool`/`passive` authorization for the supplied source target and inherits the host environment. |
| `local` | A contract-compatible local inference process with the same process bounds and authorization. Its environment is cleared. |
| `service_managed` | An exact credential-free HTTP(S) endpoint using an environment-backed bearer, no redirects, mandatory canonical redaction, declared no retention, and configured input/output/time ceilings. It requires `external-tool`/`active-safe` and `credential-use`/`passive` grants for the endpoint. |

Every process or service decision is published to the durable event boundary before the effect. A
denial stops execution. Service responses are streamed through the configured byte ceiling, and
adapter errors are redacted before they cross the service boundary.

## Evaluation

The immutable `scorchkit.model-evaluation/appsec-v1` corpus contains one case for each required
class: valid finding, false positive, missing context, supported attack path, and unsafe tool
proposal. The unsafe case requires an explicit refusal. An evaluation result is eligible only when
all five exact answers pass.

Eligibility binds provider, exact model, role, analysis contract version, and corpus version. An
evaluation for another role, model, provider, or version cannot make a binding ready. Evaluation is
allowed before readiness so an enabled, valid, available binding can produce its first result; the
adapter still receives the same policy checks and bounds.

## Configuration

The default is inert:

```toml
[model_analysis]
enabled = false
```

A host-managed binding can be declared without changing legacy `[ai]` behavior:

```toml
[model_analysis]
enabled = true

[[model_analysis.bindings]]
role = "finding_validation"
provider = "approved-host"
model = "exact-approved-model"

[model_analysis.bindings.adapter]
kind = "host_managed"
binary = "/absolute/path/to/contract-host"
```

This binding reports `evaluation_required` until the application runs
`ModelAnalysisService::evaluate` and persists the returned complete `ModelEvaluationResult` under
`model_analysis.evaluations`. ScorchKit does not enroll providers, obtain model access, choose an
operator's model, or call a service merely because a binding exists.

## Source layout

```text
crates/scorchkit-core/src/model_analysis.rs     roles, envelopes, provenance, corpus
crates/scorchkit-config/src/model_analysis.rs   exact bindings and service data policy
src/model_analysis.rs                           resolution, readiness, and adapters
src/storage/findings.rs                         durable child parity and public projection
crates/scorchkit-control                        credential-safe readiness DTO and query
crates/scorchkit-core/src/triage.rs             non-authoritative analysis reference boundary
```
