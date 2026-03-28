# ScorchKit Architecture Vision

## Four Pillars

### Pillar 1: MCP Server
ScorchKit's primary AI-native interface. Exposes scan/project/finding/analysis as MCP tools over stdio (Claude Code) and optional SSE (remote). Wraps the existing Orchestrator — no rewrite of scan logic. CLI remains for direct usage.

**Key tools:** scan, scan-module, recon, list-modules, check-tools, get-findings, analyze-findings, diff-scans, project-create, project-list, project-scan, project-findings, project-status, vuln-track, report-generate

### Pillar 2: Projects & Vulnerability Tracking
Persistent state via PostgreSQL. A project is a named collection of targets with historical scan data, tracked vulnerabilities, and posture metrics.

**Data model:** Project → Targets → ScanRecords → TrackedFindings (with lifecycle: New → Acknowledged → FalsePositive → Remediated → Verified)

**Finding fingerprinting:** Stable hash (module_id + title + target + affected_url + key evidence) for dedup across scans.

### Pillar 3: Comprehensive Scanning
Fill coverage gaps: API endpoint scanning (OpenAPI/Swagger), CORS testing, auth/session testing, version/CVE lookup, compliance mapping (OWASP Top 10 2025, PCI-DSS), executive reporting.

### Pillar 4: AI Intelligence
Three layers:
1. **Structured analysis** — JSON-typed responses (not raw text), contextual with project history
2. **Autonomous scan planning** — Claude analyzes recon, decides scan strategy, adapts based on findings
3. **Conversational security co-pilot** — Claude is the interface, ScorchKit is the engine

## Key Architecture Decisions

| Decision | Choice | Rationale |
|----------|--------|-----------|
| **Database** | PostgreSQL via sqlx | Concurrent access, JSONB for findings, full-text search, production-grade, compile-time query checking |
| **MCP Transport** | stdio + optional SSE | stdio for Claude Code, SSE for remote deployments |
| **AI Integration** | Claude via MCP (not CLI shelling) | Structured tool calls, not text piping |
| **Storage Location** | `src/storage/` | New module for DB operations |
| **MCP Module** | `src/mcp/` | Server, tools, transport |

## Implementation Order

### Phase A: Foundation (MCP + Persistence)
1. PostgreSQL storage layer (`src/storage/`)
2. Finding fingerprinting
3. Project model (CRUD, targets, config)
4. MCP server core (stdio transport, tool registration)
5. MCP tools: scan operations
6. MCP tools: project operations
7. CLI `serve` command

### Phase B: Intelligence
8. Structured AI analysis (JSON-typed)
9. Vulnerability tracking (lifecycle, dedup, trends)
10. AI-guided scan planning
11. Scan scheduling (recurring per project)
12. MCP resources (expose data as resources)

### Phase C: Comprehensive Coverage
13. API endpoint scanner (OpenAPI/Swagger)
14. CORS scanner
15. Auth/session testing module
16. Version/CVE lookup
17. Compliance mapping
18. Executive reporting (AI-generated)

### Phase D: Advanced
19. Attack chain reasoning
20. Incremental scanning (delta-based)
21. MCP SSE transport (remote mode)
22. Plugin system (user-defined modules)

## Architecture Diagram

```
┌─────────────────────────────────────────────────────┐
│                   MCP Interface                      │
│  (stdio + SSE transport, tool/resource exposure)     │
├─────────────────────────────────────────────────────┤
│                   AI Layer                           │
│  (scan planning, analysis, attack chains, co-pilot)  │
├─────────────┬───────────────┬───────────────────────┤
│  Projects   │   Scheduler   │   Vuln Tracker        │
│  (CRUD,     │   (cron,      │   (lifecycle,         │
│   targets,  │    recurring)  │    fingerprint,       │
│   history)  │               │    dedup, trends)     │
├─────────────┴───────────────┴───────────────────────┤
│              Storage (PostgreSQL / sqlx)              │
├─────────────────────────────────────────────────────┤
│              Orchestrator                            │
│  (concurrent execution, profiles, scope)             │
├──────────┬──────────┬───────────────────────────────┤
│  Recon   │ Scanner  │  Tool Wrappers                │
│  (6+)    │ (15+)    │  (21+)                        │
├──────────┴──────────┴───────────────────────────────┤
│              Engine Core                             │
│  (ScanModule, Finding, Target, ScanContext, Error)   │
└─────────────────────────────────────────────────────┘
```
