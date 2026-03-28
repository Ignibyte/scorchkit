# Runner

The runner module (`src/runner/`) handles scan execution: orchestrating modules, managing external tool subprocesses, and displaying progress.

## Files

```
runner/
  mod.rs             Module declarations
  orchestrator.rs    Module discovery, filtering, concurrent execution
  subprocess.rs      External tool subprocess management
  progress.rs        Indicatif progress spinners
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
- `crate::recon::register_modules()` - returns recon module instances
- `crate::scanner::register_modules()` - returns scanner module instances

These are concatenated into a single `Vec<Box<dyn ScanModule>>`.

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
