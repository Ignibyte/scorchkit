# Hook Architecture

ScorchKit's hook system provides scan lifecycle extensibility via external scripts. Users configure hooks in `config.toml` that fire at key points during scanning.

## Hook Points

| Point | When | Can Modify | Use Case |
|-------|------|-----------|----------|
| `pre_scan` | Before modules run | Scan configuration | Auth token injection, target discovery |
| `post_module` | After each module | Module findings | Finding filtering, enrichment, tagging |
| `post_scan` | After all modules | Nothing (fire-and-forget) | SIEM export, Slack/Jira notifications |

## Configuration

```toml
[hooks]
pre_scan = ["./hooks/authenticate.sh"]
post_module = ["./hooks/filter-false-positives.py"]
post_scan = ["./hooks/notify-slack.sh", "./hooks/export-jira.sh"]
timeout_seconds = 30  # Max time per hook (default)
fail_open = true      # Hook failure doesn't block scan (default)
```

## Protocol

- **Input:** JSON on stdin (content varies by hook point)
- **Output:** Modified JSON on stdout, or empty for no modification
- **Non-zero exit:** Hook failure — logged, scan continues (fail-open)
- **Timeout exceeded:** Same as failure — logged, scan continues

## Hook Chaining

Hooks for the same point run **sequentially**. The output of hook 1 becomes the input of hook 2. This enables composition:

```
hook 1: adds custom tags to findings
hook 2: filters findings by tags
hook 3: enriches remaining findings with JIRA links
```

## JSON Contracts

### Pre-Scan
```json
{
  "target": "https://example.com",
  "profile": "standard",
  "modules": ["headers", "ssl", "injection", ...]
}
```

### Post-Module
```json
{
  "module_id": "injection",
  "module_name": "SQL Injection Scanner",
  "findings": [ ...Finding objects... ],
  "finding_count": 3
}
```

### Post-Scan
```json
{
  "scan_id": "uuid",
  "target": "https://example.com",
  "total_findings": 15,
  "summary": { "critical": 2, "high": 5 }
}
```

## Integration with Existing Systems

- **Webhooks** (`runner/hooks.rs`): HTTP POST notifications — complementary, not replaced
- **Plugins** (`runner/plugin.rs`): Custom scan modules via TOML — different purpose (modules vs interceptors)
- **Both DAST and SAST**: Hook runner works with both Orchestrator and CodeOrchestrator

## Example: CI/CD Fail on Critical

```bash
#!/bin/bash
# hooks/fail-on-critical.sh (post_scan)
INPUT=$(cat)
CRITICAL=$(echo "$INPUT" | jq '.summary.critical')
if [ "$CRITICAL" -gt 0 ]; then
  echo "CRITICAL findings detected!" >&2
  exit 1  # Logged as warning (fail_open=true) or blocks (fail_open=false)
fi
```

## Security Model

Hooks run as the same user as ScorchKit. They have full filesystem access. Only configure hooks from trusted sources. The `fail_open` setting controls whether hook failures block scans — set to `false` for CI/CD enforcement.
