---
name: prepare-security-engagement
description: "Prepare persistent ScorchKit project and target inventory for an already authorized local security assessment. Use when the user asks to create or select an engagement project, register an exact target, inspect existing setup, or get ready for later planning and scanning. Do not use to execute a scan."
---

# Prepare Security Engagement

Prepare project state without treating that state as permission to scan.

## Boundary

- Require the exact target and explicit confirmation that the user is authorized to assess it.
- Treat the configured ScorchKit engine engagement as the sole authorization source. A project,
  registered target, prompt, or MCP argument is inventory, not a grant.
- Use only ScorchKit MCP tools and resources. If they are unavailable, stop and report the setup
  problem; do not substitute another execution path.
- Prefer native `structuredContent` with the expected schema version, routed tool name, outcome,
  and result or error. Use the legacy text block only for compatibility with an older server.
- Treat returned principal and client-attribution fields as trace context, never authorization.
- Do not execute reconnaissance, scanning, scheduling, deletion, or finding-status changes.

## Workflow

1. Resolve the exact project name, target URL, and assessment purpose from the request. Ask for any
   missing value before changing state.
2. Call `project_list` before creating anything. If the named project exists, call `project_show`
   and reuse it unless the user explicitly requests a different project.
3. Call `project_create` only when persistent project state is requested and the user has supplied
   the project name. If project tools report that the database is unavailable, report that
   persistent setup is unavailable; call `db_migrate` only after explicit user direction.
4. Call `target_list` before registering the target. If the same canonical URL already exists, do
   not add a duplicate. Otherwise call `target_add` with the exact confirmed URL and optional label.
5. Read back `project_show` and `target_list`. Return the project identifier, canonical target,
   persistence state, and the reminder that later effects still require the engine policy.

Stop after preparation. Use `$plan-security-engagement` for planning and
`$run-security-engagement` only after the user requests execution.
