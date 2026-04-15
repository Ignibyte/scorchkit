# Work Pipeline: Tutorials package

| Field | Value |
|-------|-------|
| **Pipeline Type** | Work |
| **Status** | Complete (archived) |
| **Forge Ticket** | #115 |
| **Forge Ticket ID** | 019d8e99-2941-7173-9ff5-bf3029fd9e71 |

## Phase 1-2 — PASS

Docs-only pipeline. New `docs/tutorials/` directory with 8 step-by-step task-oriented guides spanning new operators → contributors. Closes the gap between "look at all these capabilities" and "here's what to do on Tuesday morning."

| File | Topic | Audience |
|------|-------|----------|
| `01-first-scan.md` | Install, doctor, single DAST scan, read the report | New operators |
| `02-cve-correlation.md` | Stand up NVD or OSV, run an infra scan, read findings | Infra ops |
| `03-unified-assess.md` | Use `assess` for DAST + SAST + Infra in one command | Mid-level |
| `04-claude-code-workflow.md` | Conversational pentest in Claude Code | Claude users |
| `05-tls-and-dns-hygiene.md` | Run `tls_infra` + `dns_infra` against your own domain | Defenders |
| `06-extending-with-custom-modules.md` | Implement a `ScanModule` from scratch | Contributors |
| `07-extending-cve-backends.md` | Add a third `CveLookup` backend | Contributors |
| `08-ci-cd-integration.md` | Wire ScorchKit into GitHub Actions / GitLab CI | DevSecOps |

Plus a tutorials index (`docs/tutorials/README.md`) and links from the main README.

## Phase 3-6 — PASS (2026-04-15)

### Files created
- `docs/tutorials/README.md` — index
- `docs/tutorials/01-first-scan.md`
- `docs/tutorials/02-cve-correlation.md`
- `docs/tutorials/03-unified-assess.md`
- `docs/tutorials/04-claude-code-workflow.md`
- `docs/tutorials/05-tls-and-dns-hygiene.md`
- `docs/tutorials/06-extending-with-custom-modules.md`
- `docs/tutorials/07-extending-cve-backends.md`
- `docs/tutorials/08-ci-cd-integration.md`

### Files modified
- `.release/README.md` — new Tutorials section linking to all 8 guides + index
- `CHANGELOG.md` — WORK-115 bullet under `[Unreleased] / Added`

### Quality gates
- No source files touched — existing test suite (594 default tests) carries over unchanged
- Each tutorial includes a "Things that go wrong" troubleshooting table
- Every tutorial cross-links to siblings under "Where to go next"

### Notes
- `/tutorial` slash command refresh deferred to a follow-up. The eight written guides are referenced from `/tutorial` as deep-dives; updating the slash-command prompt itself can wait until users dog-food the docs and surface friction.