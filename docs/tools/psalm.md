# Psalm

Psalm is ScorchKit's optional deep PHP source-to-sink analyzer. It runs separately from PHPStan so
security taint evidence and correctness messages remain distinct.

## Install

Install Psalm for the PHP project and make a `psalm` executable available on `PATH`:

```bash
composer require --dev vimeo/psalm
vendor/bin/psalm --version
scorchkit doctor
```

When Psalm is only available as `vendor/bin/psalm`, use an operator-controlled wrapper or PATH
entry. ScorchKit does not run Composer or install project dependencies.

## Execution

The wrapper runs from the authorized PHP source root:

```text
psalm --taint-analysis --no-progress --report=<owned-report.sarif>
```

Psalm receives a 15-minute timeout and the shared process output limits. Its normal nonzero finding
exit is accepted, but the owned SARIF report must still exist and pass strict validation. The report
is limited to 64 MiB and its temporary directory is removed after the scan.

## Evidence

Each finding retains the Psalm rule ID, source region, scanner version, taint-analysis
configuration identity, every source/intermediate/sink flow location, confidence, CWE tags when
present, and redacted structured SARIF evidence. Invalid, partial, oversized, symlinked, or
scanner-failed reports fail the module rather than appearing clean.

## Selection

```bash
scorchkit code /path/to/php/project --profile thorough
scorchkit code /path/to/php/project --profile standard --modules psalm
```

Psalm is selected implicitly by `thorough` and `pentest` for PHP repositories. Other detected
languages produce a typed `not_applicable` outcome. A missing local executable produces a typed
`skipped` outcome.
