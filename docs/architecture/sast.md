# SAST Architecture

ScorchKit's SAST (Static Application Security Testing) system operates as a parallel scanning pipeline alongside the existing DAST (Dynamic Application Security Testing) system. Both share the same `Finding` type, report formats, and storage layer, but differ in their input model and module traits.

## Architecture Decision

**Decision:** Parallel `CodeModule` trait, NOT extending `ScanModule`.

**Rationale:** `ScanModule.run()` takes `&ScanContext` which contains an HTTP client and URL-based `Target`. SAST operates on file paths, not URLs, and doesn't need an HTTP client. Forcing SAST through the DAST interface would mean every SAST module ignores half its context. Clean separation means each side can evolve independently.

**Date:** 2026-04-13

## System Overview

```
CLI: scorchkit code <path>          CLI: scorchkit run <url>
         │                                    │
    CodeOrchestrator                    Orchestrator
         │                                    │
    CodeModule trait                   ScanModule trait
    CodeContext (path)                 ScanContext (URL + HTTP)
         │                                    │
    ┌────┼────────┐              ┌────────────┼────────────┐
    │    │        │              │            │            │
  sast  sast_tools             recon      scanner       tools
  (0)   (3)                    (10)       (35)          (32)
         │                                    │
         └─────────────┬──────────────────────┘
                       │
                  Vec<Finding>
                       │
              ┌────────┼────────┐
              │        │        │
           Reports   Storage   AI Analysis
```

## Key Types

### `CodeModule` trait (`engine/code_module.rs`)

Parallel to `ScanModule`. Adds `languages()` method for language-aware filtering.

### `CodeContext` (`engine/code_context.rs`)

- `path: PathBuf` — root directory to scan
- `language: Option<String>` — auto-detected from manifest files
- `manifests: Vec<PathBuf>` — discovered lockfiles/manifests
- No HTTP client, no URL-based Target

### `CodeCategory` enum

- `Sast` — static code analysis (Semgrep)
- `Sca` — software composition analysis (OSV-Scanner)
- `Secrets` — secret detection (Gitleaks)
- `Iac` — infrastructure as code (future: Checkov)
- `Container` — container scanning (future: Grype)

### `Target::from_path()`

Constructs a `Target` with `file://` URL scheme from a filesystem path. This enables reuse of `ScanResult` and all downstream infrastructure (reports, storage, AI) without duplication.

## Tool Wrappers

| Tool | Category | Output Format | Exit Code Behavior |
|------|----------|--------------|-------------------|
| Semgrep | Sast | JSON (`results` array) | 0 always |
| OSV-Scanner | Sca | JSON (`results.packages.vulnerabilities`) | 1 when vulns found |
| Gitleaks | Secrets | JSON array of leaks | 1 when leaks found |

Tools that exit non-zero for "findings found" use `subprocess::run_tool_lenient()` instead of `run_tool()`.

## Language Detection

Auto-detects from manifest files in the scan root:

| Manifest | Language |
|----------|----------|
| `Cargo.toml` | rust |
| `package.json` | javascript |
| `go.mod` | go |
| `requirements.txt` / `pyproject.toml` | python |
| `pom.xml` / `build.gradle` | java |
| `Gemfile.lock` | ruby |
| `composer.lock` | php |

Override with `--language <lang>`.

## Profiles

| Profile | Modules | Use Case |
|---------|---------|----------|
| quick | Secrets + SCA (Gitleaks, OSV-Scanner) | CI/CD, fast checks |
| standard | All SAST tools | Comprehensive code analysis |
| thorough | All SAST tools | Same as standard (grows with more tools) |

## Security: Evidence Redaction

Gitleaks findings redact secret values in evidence output. Only the first 8 characters are shown, followed by `...`. This prevents HTML/JSON reports from containing exposed credentials.
