# Brakeman

Ruby on Rails SAST — detects SQL injection, XSS, mass assignment, unsafe redirects, weak crypto, and other Rails-specific anti-patterns. The de-facto Rails security scanner. License: MIT (upstream: [presidentbeef/brakeman](https://github.com/presidentbeef/brakeman)).

## Install

```
gem install brakeman
```

Verify with `scorchkit doctor`.

## What ScorchKit surfaces

The wrapper runs `brakeman -f json -q <path>` and iterates `warnings[]`. One finding per warning:

| Brakeman `confidence` | ScorchKit severity | ScorchKit confidence |
|---|---|---|
| `High` | High | 0.9 |
| `Medium` | Medium | 0.7 |
| `Weak` / other | Low | 0.5 |

Each finding carries:

- **Title**: `brakeman <warning-type>` (e.g. `brakeman SQL Injection`)
- **Description**: Brakeman's `message` field
- **Affected**: `<app-file>:<line>`
- **Evidence**: `warning_type=<type> confidence=<level>`
- **OWASP**: A03:2021 Injection (many Brakeman warnings are injection-family; the `warning_type` in evidence disambiguates)

## How to run

```
scorchkit code /path/to/rails/app --modules brakeman
```

180s timeout. Target directory should be a Rails application root (has `config/routes.rb`, `app/`, etc.).

## Limitations vs alternatives

- **Rails-specific**. Brakeman understands Rails idioms — routes, controllers, ActiveRecord, ERB. It won't help on non-Rails Ruby (Sinatra, Roda). For generic Ruby SAST, use `semgrep` with Ruby rules.
- **`warning_type` tagging is one-size-fits-all at A03:2021 Injection**. Some Brakeman warnings are auth / crypto / info-disclosure; consult the `warning_type` field for correct triage.
- **No per-check CWE mapping yet**. Brakeman's `cwe_id` field exists for many warnings but isn't currently parsed into findings.
- **False-positive rate**. `Weak` confidence warnings are noisy by design — consider filtering on severity ≥ Medium for CI gating.
