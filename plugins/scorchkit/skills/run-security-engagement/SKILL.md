---
name: run-security-engagement
description: "Execute an explicitly authorized ScorchKit scan through MCP and preserve its lifecycle evidence. Use when the user asks to run, start, continue, resume, monitor, or cancel a DAST engagement after the exact target, profile, and module scope are known."
---

# Run Security Engagement

Execute only the approved scan and report its real terminal state.

## Boundary

- Require an explicit request to execute against the exact target. A plan, project, registered
  target, previous job, prompt, or MCP argument does not authorize effects.
- Treat the configured engine engagement as the sole authority for target, capability, profile, and
  effect class. Never weaken the request after a denial merely to make it run.
- Use only ScorchKit MCP tools and resources. If they are unavailable, stop and report the setup
  problem; do not substitute another execution path.
- Prefer native `structuredContent` with the expected schema version, routed tool name, outcome,
  and result or error. Use the legacy text block only for compatibility with an older server.
- Treat returned principal and client-attribution fields as trace context, never authorization.
- Choose the least-powerful profile that satisfies the approved plan. Use `pentest` only when the
  engagement explicitly grants credential or exploit effects.

## Workflow

1. Restate the canonical target, project if any, profile, included modules, skipped modules, and
   expected effects. Resolve any mismatch with the approved plan before calling a scan tool.
2. Call `list_modules` to validate named module IDs. Call `check_tools` before external modules or a
   `thorough`/`pentest` profile and report unavailable modules without silently replacing them.
3. For a persisted engagement, call `project_show` and `target_list`, require exact target
   membership, then call `project_scan` with the approved profile, `modules`, and `skip` selectors.
   Record the returned scan ID and its actual `modules_run` and `modules_skipped` lists.
4. For a non-persistent engagement, call `scan_job_start` with the approved target, profile,
   `modules`, and `skip`. Record the returned job ID and poll `scan_job_status` at a reasonable
   interval until a terminal state while reporting meaningful progress changes.
5. Call `scan_job_cancel` only at the user's direction. Call `scan_job_resume` only for an
   interrupted job after confirming the current engagement is unchanged and the user wants a new
   attempt. Preserve the original and successor IDs.
6. Return the terminal state, modules completed or skipped, evidence counts, error if any, and the
   scan or job ID. Treat a whole-scan error as failed. Do not describe partial, failed, cancelled,
   or interrupted work as success.

## Application supply-chain path

For an application source or artifact request, confirm the exact local path, explicit target kind,
revision if known, profile, existing private cache root, and required provider snapshot state. Use
`supply_chain_cache_status` before execution. Call `supply_chain_scan` only for the approved local
target; never convert a registry name, image reference, URL, or daemon target into a filesystem
request. Do not refresh provider data implicitly. Call `supply_chain_cache_refresh` only when the
user separately requests that effect and supplies the complete reviewed provider object list and
digests. Report `incomplete` and `degraded` coverage with every typed gap instead of describing an
empty finding set as clean.

Use `$report-security-findings` after a persisted project scan when the user requests analysis or a
report. Do not change finding lifecycle state during execution.
