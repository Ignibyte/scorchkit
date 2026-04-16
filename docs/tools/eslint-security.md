# ESLint (security plugin)

JavaScript / TypeScript security lint — runs ESLint with `eslint-plugin-security` enabling rules for `eval` with expressions, non-literal regex / filesystem paths, object-injection, and possible timing attacks. License: MIT (upstream: [eslint/eslint](https://github.com/eslint/eslint) + [eslint-community/eslint-plugin-security](https://github.com/eslint-community/eslint-plugin-security)).

## Install

ESLint plus the security plugin must be available:

```
npm install -g eslint eslint-plugin-security
```

The wrapper invokes the `eslint` binary. Verify with `scorchkit doctor`.

## What ScorchKit surfaces

The wrapper runs ESLint with `--no-eslintrc` and a hardcoded ruleset:

- `security/detect-eval-with-expression: error`
- `security/detect-non-literal-regexp: warn`
- `security/detect-non-literal-fs-filename: warn`
- `security/detect-object-injection: warn`
- `security/detect-possible-timing-attacks: warn`

It parses the JSON array output. ESLint's `severity` maps:

| ESLint `severity` | ScorchKit severity |
|---|---|
| 2 (error) | High |
| 1 (warning) | Medium |
| other | Info |

Each finding carries:

- **Title**: `<rule-id>: <message>`
- **Affected**: `<file>:<line>`
- **OWASP**: A03:2021 Injection (generic; rule-id disambiguates)
- **Remediation**: `Fix ESLint security rule violation: <rule-id>`
- **Confidence**: 0.75

## How to run

```
scorchkit code /path/to/js/project --modules eslint-security
```

120s timeout.

## Limitations vs alternatives

- **Ignores project `.eslintrc`**. This wrapper uses `--no-eslintrc` so it runs deterministically regardless of the project's own config. The downside: no custom rules, no type-aware TS linting. For richer analysis, operators invoke eslint directly against their project's config.
- **vs `semgrep`**: semgrep's JS rules go much deeper (taint tracking, cross-file) and don't require Node tooling. Prefer semgrep when the project doesn't already use ESLint.
- **Five rules only**. The `eslint-plugin-security` package has more rules; this wrapper uses a minimal stable subset to avoid noise. Operators who want the full set invoke eslint directly.
- **TypeScript support** requires `@typescript-eslint/parser` installed globally and enabled — out of scope here.
