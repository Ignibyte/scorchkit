# Work Pipeline: v3.0 Correlation Engine + AI Correlator + Risk Scoring

| Field | Value |
|-------|-------|
| **Pipeline Type** | Work |
| **Work Type** | Infrastructure |
| **Status** | Phase 3: Implement |
| **Forge Ticket** | #136, #137, #138 |

## Deliverables
- **#136**: `engine::correlation` — `AttackChain` type, `ChainStep`, rule-based `correlate()` with 10+ built-in rules
- **#137**: `ai::correlator` — Claude-driven correlation prompts, falls back to rule-based
- **#138**: `engine::risk_score` — multi-factor `risk_score: f64` on findings
