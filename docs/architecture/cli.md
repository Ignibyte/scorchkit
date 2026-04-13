# CLI

The CLI module (`src/cli/`) defines the command-line interface using clap 4 with derive macros, and the dispatch logic that maps commands to actions.

## Files

```
cli/
  mod.rs       Module declarations
  args.rs      Clap derive structs (Cli, Commands, OutputFormat)
  runner.rs    Command dispatch and execution logic
```

## Command Structure

```
scorchkit [GLOBAL OPTIONS] <COMMAND> [COMMAND OPTIONS]
```

### Global Options

| Flag | Type | Description |
|------|------|-------------|
| `-c, --config <PATH>` | `Option<PathBuf>` | Path to config.toml |
| `-v, --verbose` | Count (0-3) | Verbosity: warn → info → debug → trace |
| `-q, --quiet` | bool | Suppress all output except findings |
| `-o, --output <FORMAT>` | `Option<OutputFormat>` | `terminal` or `json` |

### Commands

**`run <target>`** - Run all default scans
```
scorchkit run https://example.com
scorchkit run example.com --modules headers,ssl
scorchkit run example.com --skip injection --analyze
```
- `target` (required) - URL, domain, or IP
- `--modules, -m` - Comma-separated list of module IDs to include
- `--skip` - Comma-separated list of module IDs to exclude
- `--analyze` - Run AI analysis after scan completes

**`recon <target>`** - Run reconnaissance modules only
```
scorchkit recon example.com
scorchkit recon example.com -m headers
```

**`scan <target>`** - Run vulnerability scanner modules only
```
scorchkit scan example.com
scorchkit scan example.com -m ssl,misconfig
```

**`analyze <report.json>`** - AI analysis of a previous scan
```
scorchkit analyze ./reports/scorchkit-uuid.json --focus remediate
```
- `--focus, -f` - Analysis type: `summary`, `prioritize`, `remediate`, `filter`

**`modules`** - List available modules
```
scorchkit modules
scorchkit modules --check-tools
```
- `--check-tools` - Also verify which external tools are installed

**`init`** - Generate a default config.toml in the current directory

## Execution Flow (`runner.rs`)

### `execute(cli: Cli) -> Result<()>`

The main dispatcher. Matches on `cli.command` and delegates:

1. **Run/Recon/Scan** → `run_scan()`:
   - Loads `AppConfig` from TOML file (or defaults)
   - Parses `Target` from the target string
   - Prints banner (target, domain, port, TLS) unless `--quiet`
   - Builds `reqwest::Client` with config (User-Agent, redirects, TLS)
   - Creates `ScanContext` (Target + Config + HTTP client)
   - Creates `Orchestrator`, registers modules, applies filters
   - For `recon` command: filters to `ModuleCategory::Recon` only
   - For `scan` command: filters to `ModuleCategory::Scanner` only
   - Runs orchestrator → `ScanResult`
   - Saves JSON report to `config.report.output_dir`
   - Prints terminal report

2. **Analyze** → Checks file exists, currently prints "not yet implemented"

3. **Modules** → `list_modules()`: Iterates all modules, prints category/id/description/tool status

4. **Init** → `init_config()`: Writes `AppConfig::default_toml()` to `config.toml`

### HTTP Client Configuration

Built in `build_http_client()`:
- User-Agent from `config.scan.user_agent`
- Timeout from `config.scan.timeout_seconds`
- Redirect policy from `config.scan.follow_redirects` + `max_redirects`
- TLS: `danger_accept_invalid_certs(false)` (always validates certs)

## OutputFormat

```rust
pub enum OutputFormat {
    Terminal,  // Colored terminal output (default)
    Json,      // JSON to stdout + saved to file
}
```

When `--output json` is specified, both the file is saved AND JSON is printed to stdout for piping.
