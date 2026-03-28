# AI Integration

**Date:** 2026-03-28
**Pipeline:** WORK-Structured-AI-Analysis (#10)

The AI module (`src/ai/`) integrates Claude via the CLI subprocess for intelligent analysis of scan findings, returning structured JSON-typed responses.

## Files

```
ai/
  mod.rs         Module declarations
  analyst.rs     AiAnalyst: Claude subprocess management + terminal rendering
  prompts.rs     AnalysisFocus enum, prompt builder with JSON schema instructions
  response.rs    Multi-tier JSON extraction, structured parsing with Raw fallback
  types.rs       17 structured types: response structs, shared enums, ProjectContext, AiAnalysis
```

## Design

ScorchKit shells out to the `claude` CLI rather than using the Anthropic API directly. This avoids API key management - it uses whatever authentication the user already has configured for Claude Code.

### Invocation Pattern

```rust
tokio::process::Command::new("claude")
    .args([
        "-p",                          // Print mode (non-interactive)
        "--output-format", "json",     // Structured JSON output
        "--model", &model,             // e.g., "sonnet"
        "--max-budget-usd", &budget,   // Cost cap
        &prompt,                       // The analysis prompt
    ])
    .output()
    .await
```

### Configuration

Controlled via `config.toml`:

```toml
[ai]
enabled = true
claude_binary = "claude"    # Path to claude CLI
model = "sonnet"            # Model for analysis
max_budget_usd = 0.50       # Cost cap per analysis
auto_analyze = false         # Auto-run after scan
```

## Analysis Modes

Each mode returns a typed struct. All prompts request JSON conforming to a documented schema.

### Summary (`SummaryAnalysis`)
Executive summary with a 0-10 risk score, key findings with business impact, attack surface assessment.

### Prioritize (`PrioritizedAnalysis`)
Findings ranked by exploitability, attack chain identification, recommended fix order.

### Remediate (`RemediationAnalysis`)
Fix steps with effort estimates (`EffortLevel`), code examples, verification steps, quick win identification.

### Filter (`FilterAnalysis`)
False positive classification (`FindingClassification`) with confidence scores (0.0-1.0) and rationale.

## Structured Response Types

```rust
pub enum StructuredAnalysis {
    Summary(SummaryAnalysis),       // risk_score, key_findings, attack_surface
    Prioritized(PrioritizedAnalysis), // ranked findings, attack_chains, fix_order
    Remediation(RemediationAnalysis), // fix steps, effort, quick_wins
    Filter(FilterAnalysis),         // classification, confidence, rationale
    Raw { content: String },        // Fallback when JSON parsing fails
}
```

### Shared Enums
- `ExploitabilityRating` — Critical/High/Medium/Low/Theoretical
- `EffortLevel` — Trivial/Low/Medium/High/Major
- `FindingClassification` — Confirmed/LikelyTrue/Uncertain/LikelyFalsePositive/FalsePositive

### JSON Extraction Strategy

Claude responses may not always be clean JSON. The multi-tier extractor handles:
1. Direct `serde_json::from_str` on the full text
2. Extract from markdown ` ```json ``` ` code fences
3. Find first balanced `{...}` block
4. Fall back to `StructuredAnalysis::Raw`

## Project Context

When analyzing within a project (`--project` flag or MCP tool), historical data is injected into the prompt:

```rust
pub struct ProjectContext {
    pub project_name: String,
    pub total_scans: usize,
    pub latest_scan_date: Option<String>,
    pub finding_trends: FindingTrends,  // total_tracked + by_status breakdown
}
```

The `ProjectContext` type lives in `ai/types.rs` (always available). The builder function `build_project_context()` lives in `storage/context.rs` (feature-gated behind `storage`).

## CLI Integration

```bash
# Auto-analyze after scan
scorchkit run https://target.com --analyze

# Analyze a previous scan report
scorchkit analyze ./reports/scorchkit-uuid.json --focus remediate

# Analyze with project history context
scorchkit analyze ./reports/scorchkit-uuid.json --focus summary --project myproject
```

## MCP Tool

The `analyze-findings` MCP tool provides project-based analysis:

```
analyze_findings(project="myproject", focus="summary")
analyze_findings(project="myproject", focus="remediate", scan_id="uuid")
```

Loads findings from PostgreSQL, builds `ProjectContext`, runs Claude analysis, returns structured JSON.

## Prompt Templates (`prompts.rs`)

Each analysis mode has a const prompt template that:

1. Sets the system context (security expert role)
2. Provides the findings as compact indexed JSON
3. Includes target metadata and scan summary statistics
4. Optionally injects project history context (scan trends, finding lifecycle)
5. Specifies the exact JSON schema for the response
6. Instructs Claude to respond with a single JSON object only
