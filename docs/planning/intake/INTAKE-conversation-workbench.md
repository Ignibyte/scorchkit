---
title: INTAKE-conversation-workbench
status: candidate
created: 2026-08-21
ticket:
pipeline_spec:
---

# Conversation-native application-security workbench

## Problem or opportunity

Codex and other MCP-capable hosts can call ScorchKit tools, but large scan summaries, evidence,
triage history, and attack paths are easier to inspect and compare visually. A custom component must
not become required for the model, bypass server authorization, or create a second result contract.

## Proposed outcome

Selected MCP/API results can return optional standards-based conversation components for scan
summaries, finding detail, evidence comparison, triage, and attack paths. Hosts without component
support continue to receive complete structured data and model-readable text.

## Candidate EARS requirements

| ID | EARS Requirement | Verification |
|---|---|---|
| REQ-001 | When a host does not render conversation components, every ScorchKit tool and workflow shall remain complete through its structured result and model-readable content. | Headless MCP, CLI, and API contract tests. |
| REQ-002 | When a compatible host requests a result view, ScorchKit shall associate a versioned UI resource with the existing tool result and shall render only validated structured content from the canonical API projection. | MCP Apps bridge, schema, and malformed-result tests. |
| REQ-003 | When a component requests an action, ScorchKit shall route it through an ordinary authenticated tool/API command and shall repeat engagement, capability, effect, CSRF-equivalent, audit, and concurrency checks server-side. | Spoofed-component and authorization tests. |
| REQ-004 | When scan, finding, evidence, triage, or attack-path data is displayed, the component shall distinguish scanner evidence, model analysis, user disposition, coverage gaps, and degraded execution. | View-model snapshots and accessibility inspection. |
| REQ-005 | When host-specific UI capabilities differ, the component shall detect the needed capability and provide a safe fallback rather than branch on a host or vendor name. | Capability and fallback matrix. |

## Scope notes

- In: optional MCP-compatible UI resources, shared view models, summary/finding/evidence/triage/
  attack-path views, accessibility, server-authorized actions, headless parity.
- Out: Rustal console, hosted scanning UI, direct database access, frontend-owned policy, or a
  requirement that Codex CLI and IDE render components.
