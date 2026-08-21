---
name: plan-security-engagement
description: "Build a reviewable ScorchKit plan for an authorized target without executing the planned scan. Use when the user asks for reconnaissance, module selection, scan strategy, profile advice, expected effects, or a plan to approve before execution."
---

# Plan Security Engagement

Build the smallest justified plan and stop at the execution boundary.

## Boundary

- Require the exact target and explicit authorization before calling `target_intelligence` or
  `plan_scan`; both may perform authorized reconnaissance, and planning is not effect-free.
- `plan_application_pentest` is the narrow exception: it only canonicalizes inert proposals and
  performs no target, credential, local-file, or subprocess effect. Its result is still not an
  authorization grant.
- Treat the configured engine engagement as authoritative. Do not infer permission from a project,
  registered target, prior scan, prompt, or plan.
- Use only ScorchKit MCP tools and resources. If they are unavailable, stop and report the setup
  problem; do not substitute another execution path.
- Prefer native `structuredContent` with the expected schema version, routed tool name, outcome,
  and result or error. Use the legacy text block only for compatibility with an older server.
- Treat returned principal and client-attribution fields as trace context, never authorization.
- Do not call `scan`, `scan_job_start`, `project_scan`, `auto_scan`, `schedule_scan`, or any finding
  status tool. Do not call `application_pentest` during planning.

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

## Code-informed application scenarios

When the request is about verifying a source/runtime finding, business invariant, or attack path,
use `plan_application_pentest` instead of proposing a generic scan profile. Supply only the reviewed
scenario and payload classes, exact `GET` or `HEAD` operation, parameter identity without a value,
persona allow/deny expectations, preconditions, source finding/path identities, deadline and
concurrency ceilings, cleanup disposition, and evidence classes. Never supply a request body,
payload program, credential, command, scanner plan, or module ID.

Return the complete canonical plan and exact plan identity. Call out manual-only, unsupported
persona, exploit-effect, credential-use, and cleanup requirements before execution. Do not alter
the proposals after review; any change requires a new plan identity.
