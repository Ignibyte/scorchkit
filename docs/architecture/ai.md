# AI adapters

The `src/ai` module provides optional planning and finding analysis. Scanner evidence remains the
source record. Provider output is a separate, labeled interpretation and cannot silently overwrite
the finding, evidence, or authorization policy.

## Provider model

`AiProvider` is the current host-neutral boundary:

```rust
#[async_trait]
pub trait AiProvider: Debug + Send + Sync {
    fn id(&self) -> &'static str;
    fn name(&self) -> &'static str;
    fn is_available(&self) -> bool;
    async fn generate(
        &self,
        system: &str,
        user: &str,
    ) -> Result<AiProviderResponse, String>;
}
```

This generic prompt interface is a compatibility stage. Roadmap batch SK-030 replaces it with typed
planning, analysis, correlation, and remediation contracts plus versioned schemas.

## Built-in adapters

| Provider | Status | Invocation properties |
|---|---|---|
| Codex CLI | default | non-interactive, approval disabled, read-only sandbox, ephemeral session, user config/rules ignored, prompt on stdin |
| Claude CLI | compatibility | one-turn print mode, JSON envelope normalization, optional cost ceiling |
| Disabled | supported | deterministic scanning continues and AI requests return an explicit unavailable result |

Both CLI adapters use the shared bounded process executor: canonical binary resolution, 120-second
timeout, 8 MiB output limits, and Unix process-tree cleanup.

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

Response parsing first tries direct JSON, then a JSON code fence, then the first balanced JSON
object. If all three fail, `StructuredAnalysis::Raw` preserves the provider text. Terminal rendering
escapes control characters; structured JSON remains lossless.

Project-backed analysis may add scan counts, dates, finding trends, and lifecycle status to the
prompt. The provider never receives database credentials or the serialized engagement.

## Failure behavior

- Planning failure falls back to the requested profile.
- Analysis failure does not change scan success or stored scanner evidence.
- An unavailable binary produces a named skip or typed error at the host layer.
- AI process execution requires the engagement's `ExternalTool` capability for the relevant target
  and effect before the process starts.

## Source layout

```text
src/ai/
  provider.rs      provider interface and bounded CLI adapters
  planner.rs       scan-plan requests and module validation
  analyst.rs       finding analysis and terminal presentation
  prompts.rs       analysis focus and schema instructions
  response.rs      provider-neutral JSON extraction
  types.rs         structured planning and analysis types
  correlator.rs    optional inference over scanner findings
  remediation.rs   remediation helper types
```
