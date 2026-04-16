# PHPStan

PHP static analysis — finds bugs, type errors, and some security-relevant issues (undefined methods, mistyped parameters, dead code). License: MIT (upstream: [phpstan/phpstan](https://github.com/phpstan/phpstan)).

## Install

```
composer global require phpstan/phpstan
# or: curl -L https://github.com/phpstan/phpstan/releases/latest/download/phpstan.phar -o /usr/local/bin/phpstan && chmod +x /usr/local/bin/phpstan
```

Verify with `scorchkit doctor`.

## What ScorchKit surfaces

The wrapper runs `phpstan analyse --error-format json --no-progress <path>` and walks `files.<path>.messages[]`. Every message becomes a **Medium** finding:

- **Title**: `PHPStan: <message>`
- **Description**: PHPStan's `message` field
- **Affected**: `<file>:<line>`
- **OWASP**: A03:2021 Injection (generic — PHPStan reports bugs not specific vulns)
- **Remediation**: PHPStan's `tip` field when present, else a generic "review and fix"
- **Confidence**: 0.7

Severity is flat Medium because PHPStan doesn't differentiate — everything it reports is a potential defect.

## How to run

```
scorchkit code /path/to/php/project --modules phpstan
```

300s timeout. PHPStan needs a working PHP environment and (for deeper analysis) a `phpstan.neon` config file in the target.

## Limitations vs alternatives

- **Bugs, not vulnerabilities**. PHPStan is a type-checker first, security tool second. For PHP SAST, pair with `semgrep` PHP rules (or paid tools like Snyk Code, Psalm security plugin).
- **Analysis level matters** — PHPStan runs at level 0 (loosest) to 9 (strictest). Without a project config, it uses the default (usually 0); the wrapper doesn't override. For deep analysis, configure `phpstan.neon` in the target.
- **Framework extensions required** for Laravel / Symfony / Doctrine awareness (`phpstan/phpstan-laravel`, etc.). The wrapper uses the stock binary.
- **Hardcoded OWASP A03** — often wrong. Treat the injection tag as a placeholder, not an assertion.
