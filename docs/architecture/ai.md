# AI adapters

The `src/ai` module provides optional planning, finding analysis, attack-chain correlation, and
remediation. Scanner evidence remains the source record. Provider output is a separate, labeled
interpretation and cannot overwrite findings, evidence, workflow state, or authorization policy.

## Provider model

`AiProvider` is the host-neutral boundary. Callers select a task through a typed request instead of
passing system and user prompt strings:

```rust
#[async_trait]
pub trait AiProvider: Debug + Send + Sync {
    fn id(&self) -> &'static str;
    fn name(&self) -> &'static str;
    fn is_available(&self) -> bool;
    async fn plan(&self, request: &PlanRequest)
        -> Result<AiProviderResponse<ScanPlan>, AiProviderError>;
    async fn analyze(&self, request: &AnalysisRequest)
        -> Result<AiProviderResponse<StructuredAnalysis>, AiProviderError>;
    async fn correlate(&self, request: &CorrelationRequest)
        -> Result<AiProviderResponse<Vec<AttackChain>>, AiProviderError>;
    async fn remediate(&self, request: &RemediationRequest)
        -> Result<AiProviderResponse<RemediationAnalysis>, AiProviderError>;
}
```

Every task uses this request envelope:

```json
{
  "schema": "scorchkit.ai/v1",
  "task": "plan",
  "input": {}
}
```

The response must repeat the exact schema and task and place its typed result under `payload`.
Missing, unsupported, unknown, and cross-task envelopes are different `AiProviderError` variants.
The decoder validates schema and task before deserializing the payload. Schema changes require a new
identifier and compatibility policy. Existing `scorchkit.ai/v1` behavior does not change silently.

## Built-in adapters

| Provider | Status | Invocation properties |
|---|---|---|
| Codex CLI | default | non-interactive, approval disabled, read-only sandbox, ephemeral session, user config/rules ignored, prompt on stdin |
| Claude CLI | compatibility | one-turn print mode, JSON envelope normalization, optional cost ceiling |
| Disabled | supported | deterministic scanning continues and AI requests return an explicit unavailable result |

Both CLI adapters use the same task renderer and decoder. Codex consumes the combined contract on
standard input. Claude receives the same system and user contract through its one-turn CLI and may
wrap the result in its outer JSON envelope. The adapters use canonical binary resolution, a
five-minute timeout, 8 MiB output limits, and Unix process-tree cleanup.

## Configuration

```toml
[ai]
enabled = true
provider = "codex"
# binary = "codex"
# model = "your-approved-model"
auto_analyze = false
```

Set `provider = "claude"` for the compatibility adapter. `max_budget_usd` applies only to Claude.
The legacy `claude_binary` key remains readable and selects the Claude adapter, but new configuration
should use `provider` and `binary`.

## Structured analysis

The supported modes are:

| Focus | Typed result |
|---|---|
| `summary` | risk score, key findings, business impact, attack surface |
| `prioritize` | ranked findings, exploitability, attack chains, fix order |
| `remediate` | concrete remediation steps, effort, verification, quick wins |
| `filter` | finding classification, confidence, and rationale |

JSON extraction accepts direct JSON, a JSON code fence, or the first typed JSON object in prefixed
text. Extraction is followed by strict envelope and payload validation. Arbitrary text is not typed
success. `StructuredAnalysis::Raw` remains only for host-owned messages such as an empty finding set
and for reading older stored values. Terminal rendering escapes control characters.

Project-backed analysis may add scan counts, dates, finding trends, and lifecycle status to the
prompt. The provider never receives database credentials or the serialized engagement.

## Failure behavior

- Planning failure falls back to the requested profile.
- Analysis failure does not change scan success or stored scanner evidence.
- Correlation failure returns the deterministic rule-engine result.
- Remediation failure returns the deterministic risk-ordered walk.
- Disabled and unavailable providers return distinct typed errors.
- AI process execution requires the engagement's `ExternalTool` capability for the relevant target
  and effect before the process starts.

## Source layout

```text
crates/scorchkit-agent/src/ai/
  prompts.rs       host-facing analysis focus vocabulary
  response.rs      JSON extraction used by the contract decoder
  types.rs         structured planning and analysis types
src/ai/
  contracts.rs     typed task requests, versioned envelopes, rendering, and decoding
  provider.rs      provider interface and bounded CLI adapters
  planner.rs       scan-plan requests and module validation
  analyst.rs       finding analysis and terminal presentation
  prompts.rs       compatibility re-exports
  response.rs      compatibility re-exports
  types.rs         compatibility re-exports
  correlator.rs    optional inference over scanner findings
  remediation.rs   remediation helper types
```
