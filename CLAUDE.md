# Claude compatibility entry point

ScorchKit no longer stores workflow state in Claude slash commands or the retired Forge service.
This file remains so Claude-based tools that inspect `CLAUDE.md` receive the same repository rules as
Codex, other agents, and humans.

Before changing code or scan behavior, read:

1. `CONSTITUTION.md`
2. `AGENTS.md`
3. `SECURITY.md`
4. `docs/planning/ROADMAP.md`

All implementation work uses the repository-owned pipeline:

```bash
bash bin/pipeline.sh doctor
bash bin/pipeline.sh status
```

Resume the one active ticket when present. Use `bash bin/pipeline.sh start PHASE` and
`bash bin/pipeline.sh pass PHASE` for transitions. Do not hand-edit phase status or move pipeline
artifacts. `bash bin/gate.sh --diff` is the validation verdict, and it must run again after archival
before delivery.

Claude remains an optional AI-analysis adapter through `[ai] provider = "claude"`. It has no special
authority over scope, effects, workflow state, evidence, or delivery.
