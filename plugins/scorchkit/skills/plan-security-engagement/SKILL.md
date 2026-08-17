---
name: plan-security-engagement
description: "Build a reviewable ScorchKit plan for an authorized target without executing the planned scan. Use when the user asks for reconnaissance, module selection, scan strategy, profile advice, expected effects, or a plan to approve before execution."
---

# Plan Security Engagement

Build the smallest justified plan and stop at the execution boundary.

## Boundary

- Require the exact target and explicit authorization before calling `target_intelligence` or
  `plan_scan`; both may perform authorized reconnaissance, and planning is not effect-free.
- Treat the configured engine engagement as authoritative. Do not infer permission from a project,
  registered target, prior scan, prompt, or plan.
- Use only ScorchKit MCP tools and resources. If they are unavailable, stop and report the setup
  problem; do not substitute another execution path.
- Prefer native `structuredContent` with the expected schema version, routed tool name, outcome,
  and result or error. Use the legacy text block only for compatibility with an older server.
- Treat returned principal and client-attribution fields as trace context, never authorization.
- Do not call `scan`, `scan_job_start`, `project_scan`, `auto_scan`, `schedule_scan`, or any finding
  status tool.

## Workflow

1. Resolve the exact target, optional project, desired depth, time budget, and prohibited effects.
   Ask before reconnaissance when authorization or the intended effect class is unclear.
2. If a project is supplied, call `project_show` and `target_list`; require the exact canonical
   target to be registered before proposing a persisted project scan.
3. Call `list_modules`. Call `check_tools` only when the user is considering `thorough`, `pentest`,
   or named external modules.
4. Call `target_intelligence` for authorized reconnaissance when needed. Preserve its scanner
   evidence and distinguish it from later provider reasoning.
5. Call `plan_scan` when AI planning is enabled and requested. If the provider is disabled or
   unavailable, say so and build a deterministic plan from module metadata and recon evidence.
6. Validate every recommended module against `list_modules`. Drop unknown IDs and retain the reason
   for each accepted or skipped module.
7. Return a plan containing the canonical target, project if any, profile, included modules,
   skipped modules, required external tools, expected effect class, rationale, time estimate, and
   unresolved authorization questions.

Present the plan for approval. Do not continue into execution unless the user's request separately
and explicitly includes execution; use `$run-security-engagement` for that phase.
