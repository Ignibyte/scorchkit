# ScorchKit Custom Rules

YAML-based pattern-matching rules that detect vulnerabilities from HTTP
response characteristics — no Rust compilation required.

## Usage

1. Copy an example rule to your `rules/` directory (or any directory).
2. Set `rules_dir` in your `scorchkit.toml`:
   ```toml
   [scan]
   rules_dir = "./rules"
   ```
3. Run a scan — the `rule-engine` module will load and run your rules:
   ```bash
   scorchkit run https://example.com
   ```

## Rule Schema

```yaml
id: unique-rule-id              # Required — unique identifier
name: Human Readable Name       # Required — becomes finding title
severity: high                  # Optional — critical/high/medium/low/info (default: medium)
description: |                  # Optional — becomes finding description
  Longer description of what this rule detects.
remediation: |                  # Optional — how to fix
  Step-by-step remediation advice. Supports {target} placeholder.

request:
  method: GET                   # Optional — HTTP method (default: GET)
  path: "/admin"                # Optional — path to append to target (default: /)
  headers:                      # Optional — additional request headers
    X-Custom: value
  body: "optional body"         # Optional — request body for POST/PUT

matchers:
  status: 200                   # Optional — exact status code match
  body_regex: "pattern"         # Optional — regex against response body
  header_regex: "name: pattern" # Optional — "header-name: regex-pattern"
```

All configured matchers must match (AND semantics).

## Example Rules

- `examples/admin-panel.yaml` — exposed admin panel
- `examples/debug-endpoint.yaml` — exposed debug endpoint
- `examples/server-header-disclosure.yaml` — server version leak via headers

## Regex

Uses Rust's `regex` crate syntax. Case-insensitive matching: `(?i)pattern`.
No backreferences (regex crate uses linear-time DFA for safety).

## Differences from TOML Plugins

| | TOML plugins | YAML rules |
|---|---|---|
| Wraps | External CLI binary | HTTP response patterns |
| Needs | Binary installed | Just the YAML file |
| Directory | `plugins_dir` | `rules_dir` |
