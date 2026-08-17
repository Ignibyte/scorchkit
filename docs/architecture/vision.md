# Architecture direction

ScorchKit is becoming a policy-gated security execution engine that can be operated by Codex, another
agent, a human CLI user, or CI without changing its safety or evidence rules.

## Four layers

1. **Policy and domain:** engagements, canonical targets, capabilities, effects, findings, evidence,
   and audit decisions.
2. **Execution:** bounded HTTP, process, filesystem, credential, infrastructure, and cloud adapters
   under shared job control.
3. **Interfaces and state:** CLI, local stdio MCP, projects, schedules, jobs, and storage.
4. **Reasoning hosts:** Codex first, Claude compatibility, and other hosts through typed contracts.

```text
Codex / Claude compatibility / other hosts / humans / CI
                           |
                 CLI and typed stdio MCP
                           |
               engagement-gated job control
                           |
             shared executor and family adapters
              /          |          |       \
            DAST        SAST      Infra     Cloud
              \          |          |       /
              evidence, findings, and artifacts
                           |
                storage, correlation, reports
```

## Decisions already in force

| Decision | Current choice |
|---|---|
| Authorization | Fail-closed `Engagement` in engine code; prompts and project records are not grants |
| Development workflow | Repository ticket/spec/notes/AAR state with Git-enforced exact-worktree receipts |
| Preferred host | Codex, through a thin repository skill and optional AI adapter |
| Compatibility | Claude adapter retained outside authorization and workflow policy |
| Local agent protocol | MCP over stdio |
| Remote protocol | Unsupported until authenticated principal binding and TLS policy exist |
| Persistence | PostgreSQL today; storage trait and stateless MCP are planned |
| Scanner evidence | Preserved independently from agent-generated interpretation |
| Supported OS | Linux and macOS until Windows Job Object process ownership is implemented |

## Build order

The detailed dependency graph and executable exit evidence live in
[`docs/planning/ROADMAP.md`](../planning/ROADMAP.md). The architectural order is:

1. finish the policy and quality baseline;
2. unify execution, cancellation, and jobs;
3. abstract storage and make scan-only MCP stateless;
4. add typed provider-neutral reasoning contracts and the Codex plugin;
5. extract crates only after contracts make movement behavior-preserving;
6. consolidate scanners and version evidence/report schemas;
7. add authenticated remote operation and release hardening;
8. consider quasi-pentest effects only after cleanup, audit, and authorization are proven.

The project is a refactor, not a rewrite. Each batch must leave the tested main product usable, and
compatibility adapters remain until replacement contracts prove equivalent behavior.
