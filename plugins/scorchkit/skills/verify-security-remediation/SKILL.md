---
name: verify-security-remediation
description: "Verify claimed ScorchKit remediation with a focused follow-up project scan and evidence comparison. Use when the user asks to retest fixed findings, confirm remediation, detect regressions, or move evidence-supported findings from remediated to verified."
---

# Verify Security Remediation

Verify with a comparable scan; never equate a claimed fix with evidence.

## Boundary

- Require the project, exact target, finding IDs, and explicit user direction to run the follow-up
  scan. A remediated status or prior authorization record does not authorize a new effect.
- Treat the configured engine engagement as authoritative and require the target to remain an exact
  registered project target. Do not broaden scope or profile to obtain a result.
- Use only ScorchKit MCP tools and resources. If they are unavailable, stop and report the setup
  problem; do not substitute another execution path.
- Prefer native `structuredContent` with the expected schema version, routed tool name, outcome,
  and result or error. Use the legacy text block only for compatibility with an older server.
- Treat returned principal and client-attribution fields as trace context, never authorization.
- Call `finding_update_status` only after the follow-up evidence supports the transition and the
  user's verification request covers that finding.

## Workflow

1. Call `project_show`, `target_list`, and `project_findings` with status `remediated`. Resolve the
   exact target and requested finding IDs; do not retest unrelated findings by default.
2. Call `finding_show` for each requested finding. Record its module ID, affected target, evidence,
   lifecycle status, `scan_id`, `last_seen`, and `seen_count` as the baseline.
3. Derive the narrow module list needed to reproduce the original checks and validate it with
   `list_modules`. Use the original profile when known; never choose a more powerful profile merely
   for convenience.
4. Call `project_scan` once for the same registered target with the focused modules and approved
   profile. Record the new scan ID and actual modules run, skipped, or failed.
5. Call `project_show`, `project_status`, `project_findings`, and `finding_show` again. A finding
   whose `scan_id` advances to the new scan reappeared and is not fixed. A finding is eligible for
   verification only when all reproducing modules completed successfully, the new scan is terminal,
   and its stored `scan_id` and `last_seen` did not advance.
6. Call `finding_update_status` with `verified` only for eligible requested findings. Leave
   persistent, untested, skipped, failed, or ambiguous findings unchanged.
7. Report the baseline and follow-up scan IDs, modules and evidence compared, verified findings,
   persistent findings, unverified findings with reasons, and any regressions.

If evidence is incomplete, say that verification is inconclusive. Do not convert absence caused by
a skipped or failed module into a verified result.
