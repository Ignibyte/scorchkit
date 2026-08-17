# 04 — Agent workflow

**Goal:** use Codex as the preferred development and analysis host while keeping ScorchKit's
authorization, evidence, and delivery state independent of the agent.

Codex reads the repository's `AGENTS.md` before work and can select the repo-scoped
`.agents/skills/scorchkit-pipeline` workflow when a change is requested. This matches the official
[OpenAI AGENTS.md guidance](https://developers.openai.com/codex/guides/agents-md) and
[skills guidance](https://developers.openai.com/codex/skills).

## 1. Open the repository

Open the ScorchKit repository in Codex. Ask for the current workflow state before requesting a
change:

```text
Read the repository instructions and show the active ScorchKit ticket and pipeline phase.
```

The expected source of truth is the repository, not the conversation:

- `CONSTITUTION.md` defines binding quality and delivery rules;
- `AGENTS.md` defines host-neutral working rules;
- `SECURITY.md` defines effect authorization;
- `docs/planning/ROADMAP.md` orders baseline and technical-debt work;
- `bin/pipeline.sh` owns ticket transitions;
- `bin/gate.sh` owns the delivery verdict.

## 2. Request a repository change

Give the outcome and constraints, not a vendor-specific slash command:

```text
Add a source scanner for <behavior>. Use the ScorchKit pipeline, write observable requirements,
preserve the engagement boundary, add regression tests, and stop before commit or push.
```

Codex should resume the one active ticket or create one through the pipeline script. Plan and design
confirmation, inspect findings, validation commands, and the AAR remain in versioned files. Other
agents and humans can continue the same work without reconstructing a chat transcript.

## 3. Ask for an authorized scan

State the ownership or permission boundary, exact target, and allowed effect class. A useful request
looks like:

```text
I own the loopback service at http://127.0.0.1:8080. Review the generated engagement and run only
the quick profile. Do not broaden scope or contact another address.
```

The statement gives Codex context. It does not bypass ScorchKit. The CLI or library must still load
an engagement that authorizes the canonical target, capability, and effect. Redirects, DNS answers,
derived native targets, subprocesses, code paths, credentials, and cloud resources remain subject to
their code-level checks.

## 4. Separate evidence from analysis

Ask the agent to retain the raw report and label any interpretation:

```text
Review reports/current.json. Keep scanner evidence unchanged. Separate confirmed observations,
inferences, likely false positives, and remediation suggestions.
```

ScorchKit's optional AI layer follows the same rule. Codex is the default CLI adapter; the Claude
adapter remains available for compatibility. Neither adapter can grant effects or silently rewrite
scanner evidence.

## 5. Finish through the delivery receipt

For implementation work, ask Codex to continue through the repository gates:

```text
Continue the active ticket through inspection and validation. Run the canonical diff gate, update
durable documentation and the AAR, archive through the pipeline script, then rerun the diff gate and
show the matching receipt. Do not commit or push.
```

The required path is:

```text
create → plan → design → implement → inspect → validate → complete → delivery
```

A green message is not delivery evidence. The exact worktree must match the receipt written by a
real DIFF or FULL gate.

## 6. Use another agent

An agent that does not load Codex skills can still follow `AGENTS.md` and run the same scripts. Do
not recreate `.claude/commands`, Forge state, or another agent-owned ticket store. Agent-specific
adapters may improve ergonomics, but ScorchKit remains the effect and evidence authority.

## Troubleshooting

| Symptom | Check |
|---|---|
| Agent proposes work without a ticket | Ask it to read `AGENTS.md` and run `bash bin/pipeline.sh status`. |
| Agent treats a prompt as scan permission | Stop the run and create or correct the ScorchKit engagement. |
| Agent claims green without a receipt | Run `bash bin/pipeline.sh receipt`; stale or missing means delivery is unproven. |
| Guidance looks stale | Start a new Codex run from the repository root so `AGENTS.md` discovery runs again. |
