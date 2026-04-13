# Runner

The runner module (`src/runner/`) handles scan execution: orchestrating modules, managing external tool subprocesses, and displaying progress.

## Files

```
runner/
  mod.rs             Module declarations
  orchestrator.rs    Module discovery, filtering, concurrent execution
  subprocess.rs      External tool subprocess management
  progress.rs        Indicatif progress spinners
  hooks.rs           Webhook notification system for scan events
  plugin.rs          TOML-based user plugin system
```

## Orchestrator (`orchestrator.rs`)

The orchestrator is the engine that drives a scan. It discovers modules, applies user filters, checks tool availability, and runs modules sequentially (concurrent execution planned via `max_concurrent_modules`).

### Public API

```rust
// Get all registered modules (recon + scanner)
pub fn all_modules() -> Vec<Box<dyn ScanModule>>

pub struct Orchestrator {
    ctx: ScanContext,
    modules: Vec<Box<dyn ScanModule>>,
}

impl Orchestrator {
    pub fn new(ctx: ScanContext) -> Self
    pub fn register_default_modules(&mut self)
    pub fn filter_by_category(&mut self, category: ModuleCategory)
    pub fn filter_by_ids(&mut self, ids: &[String])
    pub fn exclude_by_ids(&mut self, ids: &[String])
    pub async fn run(&self, quiet: bool) -> Result<ScanResult>
}
```

### Execution Flow (`run()`)

1. Generate a UUID v4 scan ID and record start time
2. For each registered module:
   a. If module requires an external tool, check if it's installed via `which`
   b. If tool not found, skip the module and record the reason
   c. Start a progress spinner (unless `--quiet`)
   d. Call `module.run(&self.ctx).await`
   e. On success: record findings, finish spinner with count
   f. On error: record skip reason, finish spinner with error message
3. Sort all findings by severity (Critical first, via `Ord` on `Severity`)
4. Build and return `ScanResult`

### Module Discovery

`all_modules()` calls:
- `crate::recon::register_modules()` - returns recon module instances (6 modules)
- `crate::scanner::register_modules()` - returns scanner module instances (24 modules)
- `crate::tools::register_modules()` - returns external tool wrapper instances (32 modules)

These are concatenated into a single `Vec<Box<dyn ScanModule>>` (62 built-in modules).

Additionally, `register_default_modules()` calls `plugin::load_plugins()` to load any user-defined plugins from the configured plugins directory.

### Filtering

Filters modify the orchestrator's internal module list:

- `filter_by_category(Recon)` - keeps only recon modules (used by `scorchkit recon`)
- `filter_by_category(Scanner)` - keeps only scanner modules (used by `scorchkit scan`)
- `filter_by_ids(["headers", "ssl"])` - keeps only modules with matching IDs (used by `--modules`)
- `exclude_by_ids(["injection"])` - removes modules with matching IDs (used by `--skip`)

## Subprocess Management (`subprocess.rs`)

Provides a reusable function for running external tools as subprocesses.

### API

```rust
pub struct ToolOutput {
    pub stdout: String,
    pub stderr: String,
    pub exit_code: i32,
    pub duration: Duration,
}

pub async fn run_tool(
    tool_name: &str,
    args: &[&str],
    timeout: Duration,
) -> Result<ToolOutput>
```

### Behavior

1. **Tool existence check** - runs `which <tool>` to verify the binary is in PATH
2. **Spawn** - uses `tokio::process::Command` for async subprocess execution
3. **Timeout** - wraps the execution in `tokio::time::timeout()`
4. **Capture** - collects stdout and stderr as strings
5. **Exit status** - returns `ScorchError::ToolFailed` on non-zero exit
6. **Timeout** - returns `ScorchError::Cancelled` if the tool exceeds the timeout

### Error Handling

| Scenario | Error |
|----------|-------|
| Tool not in PATH | `ScorchError::ToolNotFound { tool }` |
| Non-zero exit | `ScorchError::ToolFailed { tool, status, stderr }` |
| Timeout exceeded | `ScorchError::Cancelled { reason }` |
| Spawn failure | `ScorchError::ToolFailed { tool, status: -1, stderr }` |

### Usage Pattern (in tool wrappers)

```rust
let output = subprocess::run_tool(
    "nmap",
    &["-sV", "-oX", "-", target],
    Duration::from_secs(300),
).await?;

let findings = parse_nmap_xml(&output.stdout)?;
```

## Progress Reporting (`progress.rs`)

Uses the `indicatif` crate for terminal progress spinners.

### Functions

```rust
// Create a cyan spinner with "Running {module_name}..." message
pub fn module_spinner(module_name: &str) -> ProgressBar

// Finish with "Module - N finding(s)" or "no issues found"
pub fn finish_success(pb: &ProgressBar, module_name: &str, finding_count: usize)

// Finish with "Module - ERROR: {error}"
pub fn finish_error(pb: &ProgressBar, module_name: &str, error: &str)
```

Spinners tick every 100ms. When `--quiet` is set, the orchestrator skips creating spinners entirely.

## Webhook Notifications (`hooks.rs`)

Fires JSON payloads to configured webhook URLs when scan lifecycle events occur. Notifications are async and fire-and-forget -- failures are logged as warnings but never block scanning.

### ScanEvent

```rust
pub enum ScanEvent {
    ScanStarted { scan_id, target, profile, module_count },
    ScanCompleted { scan_id, target, finding_count, duration_seconds },
    FindingDiscovered { scan_id, module_id, severity, title, affected_target },
}
```

Events serialize with a `"event"` tag field (e.g., `"event": "scan_started"`).

### WebhookConfig

```rust
pub struct WebhookConfig {
    pub url: String,         // URL to POST event payloads to
    pub events: Vec<String>, // Optional filter (empty = all events)
}
```

### Delivery

```rust
pub fn notify(webhooks: &[WebhookConfig], event: &ScanEvent)
```

Spawns a `tokio::spawn` task for each matching webhook. Each task POSTs the JSON-serialized event with `Content-Type: application/json`. If the webhook config has a non-empty `events` list, only matching event types are delivered.

## Plugin System (`plugin.rs`)

Allows users to define custom scan modules via TOML files without writing Rust code.

### PluginDef

Plugin definitions are TOML files placed in the configured plugins directory:

```toml
id = "custom-check"
name = "My Custom Check"
description = "Runs a custom security check"
category = "scanner"       # "recon" or "scanner"
command = "my-tool"
args = ["--json", "{target}"]
timeout_seconds = 120
output_format = "lines"    # "lines", "json_lines", or "json"
severity = "medium"
```

The `{target}` placeholder in `args` is substituted with the scan target URL at runtime.

### PluginModule

Wraps a `PluginDef` and implements `ScanModule`. Always reports `requires_external_tool() = true` with the `command` field as the required tool. The module runs the command via `subprocess::run_tool()` and parses output according to `output_format`:

- **`lines`** -- Consolidates all output lines into a single finding with a count summary
- **`json_lines`** -- Each line is parsed as a JSON object; `title`, `severity`, and `description` fields are extracted
- **`json`** -- Entire output is parsed as a JSON array; each element becomes a finding

### Loading

```rust
pub fn load_plugins(dir: &Path) -> Vec<Box<dyn ScanModule>>
```

Discovers `.toml` files in the given directory, parses each as a `PluginDef`, and wraps them in `PluginModule`. Invalid files are logged and skipped. Called by `Orchestrator::register_default_modules()` when `config.scan.plugins_dir` is set.
