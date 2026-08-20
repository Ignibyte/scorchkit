# CodeQL

CodeQL is ScorchKit's optional deep source analyzer for JavaScript/TypeScript, Python, and Ruby.
ScorchKit uses the locally installed CodeQL CLI bundle and its bundled security-extended query
suites. It does not download query packs, submit results to a hosted service, or run a target build
command.

## Install

Install the complete CodeQL CLI bundle from GitHub, review the license for your use, and place the
`codeql` executable on `PATH`:

```bash
codeql version
scorchkit doctor
```

ScorchKit does not install or license CodeQL automatically. A standalone binary without the bundled
language extractors and query packs is not sufficient.

## Execution

For each supported detected language, ScorchKit:

1. creates a private temporary database with an explicit language, source root,
   `--build-mode=none`, two threads, 4096 MiB RAM, and a 15-minute timeout;
2. analyzes that database as SARIF with the bundled security-extended suite, two threads,
   4096 MiB RAM, `--no-download`, and a 20-minute timeout;
3. reads at most 64 MiB from the owned SARIF file and removes the report and database directory.

JavaScript and TypeScript share one extractor and therefore one database in a mixed project. PHP is
not supported by this adapter because it is not part of the locked safe no-build set. Use Psalm for
PHP.

## Evidence

The strict SARIF boundary preserves:

- every code flow, thread flow, and ordered location;
- source regions and artifact-index paths;
- query ID, query metadata digest, CLI version, suite identity, automation ID, and revision;
- tool severity and precision-derived confidence;
- CWE tags when the query supplies them;
- a recursively redacted structured copy of the SARIF result and rule.

Missing reports, oversized files, symlinks, invalid or partial SARIF, and scanner-reported failed
invocations fail the module. A valid empty SARIF report remains a clean result.

## Selection

```bash
scorchkit code /path/to/source --profile thorough
scorchkit code /path/to/source --profile standard --modules codeql
```

CodeQL is selected implicitly by `thorough` and `pentest`. A valid explicit module ID can select
it under another valid profile. Unsupported or undetected languages produce a typed
`not_applicable` outcome. A missing local CLI produces a typed `skipped` outcome.
