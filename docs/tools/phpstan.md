# PHPStan

PHPStan is a PHP correctness and type analyzer. ScorchKit reports its output as correctness
evidence. It does not label every PHPStan message as an injection vulnerability and does not invent
an OWASP category or CWE.

## Install

```bash
composer global require phpstan/phpstan
phpstan --version
```

The `phpstan` executable must be on `PATH`. Run `scorchkit doctor` after installation.

## Execution and findings

The wrapper runs:

```text
phpstan analyse --error-format json --no-progress <source-root>
```

The process has a five-minute timeout and accepts PHPStan's normal nonzero finding exit. Each valid
message becomes an Info-severity correctness finding with its file, positive line number, optional
PHPStan identifier, optional tip, and redacted structured message. Empty `files` or empty message
lists are clean. Invalid JSON, missing file/message shapes, invalid line numbers, and PHPStan
analysis errors fail the module.

## Selection

```bash
scorchkit code /path/to/php/project --profile standard --modules phpstan
```

PHPStan is a fast PHP analyzer and is eligible for the `standard` profile. Project configuration
still controls PHPStan's analysis level and framework extensions.

Use Psalm for PHP security taint analysis. Running both is intentional: PHPStan supplies correctness
signals while Psalm supplies source-to-sink security evidence.
