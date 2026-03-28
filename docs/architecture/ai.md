# AI Integration

The AI module (`src/ai/`) integrates Claude via the CLI subprocess for intelligent analysis of scan findings. Planned for Phase 6.

## Files

```
ai/
  mod.rs         Module declarations (placeholder)
  analyst.rs     Claude subprocess management (Phase 6)
  prompts.rs     Prompt templates for analysis types (Phase 6)
  response.rs    AI response parsing and structured types (Phase 6)
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

### Summary
Generate an executive summary of findings. Useful for reports to stakeholders.

**Prompt approach:** Provide all findings as JSON, ask for a prioritized summary with business impact assessment.

### Prioritize
Severity assessment and attack path analysis. Claude evaluates which findings are most exploitable in combination.

**Prompt approach:** Provide findings + target context, ask for exploitation likelihood ranking and attack chain identification.

### Remediate
Detailed fix recommendations tailored to the detected technology stack.

**Prompt approach:** Provide findings + any tech fingerprinting results, ask for specific configuration changes, code fixes, or architecture recommendations.

### Filter
False positive identification. Claude reviews findings and flags likely false positives with reasoning.

**Prompt approach:** Provide findings with evidence, ask Claude to assess each finding's validity and confidence level.

## CLI Integration

```bash
# Auto-analyze after scan
scorchkit run https://target.com --analyze

# Analyze a previous scan report
scorchkit analyze ./reports/scorchkit-uuid.json --focus remediate
```

## Planned Architecture

```rust
pub struct AiAnalyst {
    claude_binary: String,
    model: String,
    max_budget: f64,
}

impl AiAnalyst {
    pub async fn analyze(
        &self,
        findings: &[Finding],
        focus: AnalysisFocus,
    ) -> Result<AiAnalysis>
}

pub enum AnalysisFocus {
    Summary,
    Prioritize,
    Remediate,
    FilterFalsePositives,
}

pub struct AiAnalysis {
    pub focus: AnalysisFocus,
    pub content: String,           // Raw analysis text
    pub prioritized: Vec<String>,  // Ordered finding IDs (for Prioritize)
    pub false_positives: Vec<String>, // Finding IDs flagged (for Filter)
}
```

## Prompt Templates (`prompts.rs`)

Each analysis mode will have a structured prompt template that:

1. Sets the system context (security expert role)
2. Provides the findings as structured JSON
3. Includes target metadata (domain, tech stack if known)
4. Specifies the desired output format
5. Asks for specific deliverables based on the focus mode
