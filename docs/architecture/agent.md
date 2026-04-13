# Agent SDK Support

The `agent` module (`src/agent/`) provides configuration, system prompts, and manifest generation for integrating ScorchKit with the Claude Agent SDK. It does not run agents directly -- it produces the configuration that Agent SDK clients (Python/TypeScript) consume.

## Files

```
agent/
  mod.rs         Manifest generation and module declarations
  config.rs      AgentConfig struct and builder
  prompt.rs      AGENT_SYSTEM_PROMPT constant (PTES methodology)
```

## AgentConfig (`config.rs`)

Controls what the agent is allowed to scan, how deep to go, and what safety constraints apply.

```rust
pub struct AgentConfig {
    pub authorized_targets: Vec<String>,   // Exact domains, wildcards, CIDRs
    pub max_depth: String,                 // "quick", "standard", "thorough"
    pub require_project: bool,             // Require project persistence (default: true)
    pub enable_analysis: bool,             // Enable AI analysis after scanning (default: true)
    pub max_concurrent_scans: usize,       // Max parallel scans (default: 1)
    pub scan_delay_seconds: u64,           // Rate limiting delay (default: 0)
    pub project_name: Option<String>,      // Project name (auto-generated if None)
    pub database_url: Option<String>,      // Database URL for persistence
}
```

**Builder pattern:**
```rust
let config = AgentConfig::new(vec!["example.com".to_string()])
    .with_depth("thorough")
    .with_project("my-assessment")
    .with_database_url("postgres://...");
```

`AgentConfig::default()` creates a config with no authorized targets, `"standard"` depth, project persistence required, analysis enabled, and single-scan concurrency.

## System Prompt (`prompt.rs`)

`AGENT_SYSTEM_PROMPT` is a `&'static str` constant encoding the PTES (Penetration Testing Execution Standard) methodology as structured instructions for Claude. It defines seven phases:

1. **Pre-Engagement** -- Create project, register targets, confirm scope
2. **Intelligence Gathering** -- Passive/active recon, tech stack analysis
3. **Threat Modeling** -- AI-guided scan planning, high-value target identification
4. **Vulnerability Analysis** -- Execute scans with recommended profiles
5. **Analysis & Correlation** -- Summarize, prioritize, correlate findings into attack chains
6. **Reporting** -- Remediation steps, executive metrics
7. **Remediation Support** -- Actionable fix prioritization by risk

The prompt includes built-in safety constraints:
- Rate limiting between scan operations
- Scope enforcement against `authorized_targets`
- Detection and analysis only -- no exploitation
- Evidence preservation via project persistence
- Immediate escalation for critical findings (RCE, SQLi, auth bypass)

## Manifest Generation (`mod.rs`)

```rust
pub fn generate_manifest(config: &AgentConfig) -> String
```

Produces a JSON manifest containing everything an Agent SDK client needs:

```json
{
    "name": "scorchkit-agent",
    "version": "<crate version>",
    "description": "Autonomous penetration testing agent powered by ScorchKit",
    "mcp_server": {
        "command": "scorchkit",
        "args": ["serve"],
        "transport": "stdio"
    },
    "system_prompt": "<PTES methodology prompt>",
    "agent_config": { ... },
    "capabilities": {
        "tools": true,
        "resources": true,
        "prompts": true
    },
    "safety": {
        "authorized_targets": [...],
        "max_depth": "standard",
        "require_project": true,
        "scope_enforcement": "strict",
        "exploitation": "disabled",
        "rate_limiting": false
    }
}
```

The `mcp_server` block tells the Agent SDK client how to spawn ScorchKit's MCP server (`scorchkit serve` over stdio transport). The `safety` block enforces constraints at both the prompt level and the manifest level.

## Integration

Agent SDK clients consume the manifest to set up an autonomous pentest session:

```python
# Python Agent SDK example
from claude_agent_sdk import Agent
import json

# Generate manifest from ScorchKit
manifest = json.loads(subprocess.check_output(["scorchkit", "agent-manifest",
    "--target", "example.com", "--depth", "thorough"]))

agent = Agent(
    mcp_servers=[manifest["mcp_server"]],
    system_prompt=manifest["system_prompt"],
)
```

The agent then follows the PTES methodology using ScorchKit's MCP tools, with scope enforcement and safety constraints applied at every step.
