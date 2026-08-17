---
name: report-security-findings
description: "Turn persisted ScorchKit scanner evidence into a technical or executive report without changing project state. Use when the user asks to summarize findings, explain risk, prioritize issues, correlate attack paths, review posture, or produce remediation guidance from an existing project or scan."
---

# Report Security Findings

Lead with scanner evidence, then add clearly labeled interpretation.

## Boundary

- Use only ScorchKit MCP tools and resources. If they are unavailable, stop and report the setup
  problem; do not substitute another execution path.
- Read existing project state only. Do not call scanning, project/target mutation, scheduling,
  database migration, deletion, or `finding_update_status`.
- Preserve finding IDs, scanner module IDs, severity, confidence, evidence, target, scan identity,
  and lifecycle state. Do not turn provider output into scanner evidence.

## Workflow

1. Resolve the project and optional scan ID. Call `project_show` to establish the project, targets,
   scan history, and current counts.
2. Call `project_status` and `project_findings`. Apply severity or lifecycle filters only when the
   user asks; otherwise retain the complete visible set.
3. Call `finding_show` for every finding discussed in detail. Base vulnerability claims and
   remediation statements on its stored evidence, not the title alone.
4. Call `correlate_findings` when attack paths or cross-finding priority matter. Label correlation
   as derived analysis and retain the contributing finding IDs.
5. Call `analyze_findings` only when AI analysis is enabled and useful for the requested report.
   Label its output as provider interpretation, include model metadata when returned, and keep any
   provider failure separate from the scanner result.
6. Produce the requested audience level. Include scope and scan identity, evidence-backed counts,
   top risks, affected targets, uncertainty, attack chains when supported, remediation priorities,
   and explicit limitations. Keep severity and confidence distinct.

Report empty, partial, stale, or failed evidence honestly. Never infer that a missing detail was
tested.
