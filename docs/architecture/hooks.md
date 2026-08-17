# Lifecycle hooks

Lifecycle hooks are configured local executables. They receive one JSON value on standard input and
may return one JSON value on standard output. They run through the policy-sealed, bounded process
executor and therefore require `ExternalTool` authorization for the DAST target and profile effect.

## Hook points

| Setting | Runs | Input | Output behavior |
|---|---|---|---|
| `pre_scan` | before modules start | target, profile, runnable module IDs | parsed but not applied in the current runner |
| `post_module` | after each successful module | module identity and findings | a valid `findings` array replaces that module's findings |
| `post_scan` | after findings are collected | scan identity, target, count, critical/high summary | ignored after completion |

Scripts at one hook point run sequentially. Valid JSON output from one script becomes the next
script's input. Empty output is a passthrough. Invalid JSON is a hook failure.

## Configuration

```toml
[hooks]
pre_scan = ["/opt/scorchkit/hooks/check-window"]
post_module = ["/opt/scorchkit/hooks/enrich-findings"]
post_scan = ["/opt/scorchkit/hooks/export-summary"]
timeout_seconds = 30
fail_open = false
```

`fail_open = true` logs a terminal-escaped warning and continues. `false` returns a typed hook error
and aborts the scan. Use fail-closed behavior when a hook represents an authorization, maintenance
window, or evidence-handling requirement.

## Process controls

Each invocation has a timeout, bounded stdout and stderr, canonical executable resolution, no shell
interpolation, and Unix process-group cleanup. Hook output is untrusted until JSON parsing succeeds.
Secrets should not be written to stdout or stderr because hook output can enter logs and reports.

## Webhooks

Webhook configuration is retained only for configuration compatibility. ScorchKit does not send
outbound webhook requests. A future delivery service must use an engagement-bound HTTP client,
authorize redirects and resolved addresses, apply the common redaction policy, and bound its queue
and retry behavior outside scan execution.
