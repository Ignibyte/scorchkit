# External Tool Wrappers

Tool wrappers live in `src/tools/`. Each wrapper implements `ScanModule` with `requires_external_tool() = true` and delegates the actual scanning to an external binary.

## Files

```
tools/
  mod.rs           Module declarations (placeholder)
  nmap.rs          nmap wrapper (Phase 5)
  nikto.rs         nikto wrapper (Phase 5)
  sqlmap.rs        sqlmap wrapper (Phase 5)
  nuclei.rs        nuclei wrapper (Phase 5)
  feroxbuster.rs   feroxbuster wrapper (Phase 5)
  sslyze.rs        sslyze/testssl wrapper (Phase 5)
```

## Wrapper Pattern

Every tool wrapper follows the same structure:

```rust
#[derive(Debug)]
pub struct ToolNameModule;

#[async_trait]
impl ScanModule for ToolNameModule {
    fn name(&self) -> &'static str { "Tool Display Name" }
    fn id(&self) -> &'static str { "tool-id" }
    fn category(&self) -> ModuleCategory { ModuleCategory::Scanner }
    fn description(&self) -> &'static str { "What it does" }

    fn requires_external_tool(&self) -> bool { true }
    fn required_tool(&self) -> Option<&str> { Some("tool-binary-name") }

    async fn run(&self, ctx: &ScanContext) -> Result<Vec<Finding>> {
        // 1. Build arguments for the tool
        let args = build_args(&ctx.target, &ctx.config);

        // 2. Run the tool via subprocess
        let output = subprocess::run_tool(
            "tool-binary-name",
            &args,
            Duration::from_secs(timeout),
        ).await?;

        // 3. Parse tool output into findings
        parse_output(&output.stdout, ctx.target.url.as_str())
    }
}

// Tool-specific argument builder
fn build_args(target: &Target, config: &AppConfig) -> Vec<String> { ... }

// Tool-specific output parser
fn parse_output(raw: &str, target_url: &str) -> Result<Vec<Finding>> { ... }
```

## How the Orchestrator Handles Tool Wrappers

1. Calls `module.requires_external_tool()` → `true`
2. Calls `module.required_tool()` → `Some("nmap")`
3. Runs `which nmap` to check availability
4. If not found: skips module, records `("nmap", "external tool 'nmap' not found")` in `modules_skipped`
5. If found: runs the module normally

This means tool wrappers are zero-cost if the tool isn't installed. Users see them in `scorchkit modules --check-tools` and can install as needed.

## Subprocess API

All wrappers use `runner::subprocess::run_tool()`:

```rust
pub async fn run_tool(
    tool_name: &str,   // Binary name or path
    args: &[&str],     // Command arguments
    timeout: Duration, // Max execution time
) -> Result<ToolOutput>
```

Returns `ToolOutput { stdout, stderr, exit_code, duration }` on success.

## Tool Path Override

Users can override tool binary paths in `config.toml`:

```toml
[tools]
nmap = "/usr/local/bin/nmap"
sqlmap = "/opt/sqlmap/sqlmap.py"
```

When implementing a wrapper, check `ctx.config.tools.<tool>` for a custom path before falling back to the binary name.

## Planned Wrappers

### nmap (`nmap.rs`)
- **Binary:** `nmap`
- **Args:** `-sV -oX -` (service version detection, XML output to stdout)
- **Parse:** XML output for open ports, service versions, OS detection
- **Findings:** Open ports with service info, outdated service versions

### nikto (`nikto.rs`)
- **Binary:** `nikto`
- **Args:** `-h <target> -Format json -output -`
- **Parse:** JSON output for web server vulnerabilities
- **Findings:** Default files, misconfigurations, known vulnerabilities

### sqlmap (`sqlmap.rs`)
- **Binary:** `sqlmap`
- **Args:** `-u <target> --batch --output-dir=<tempdir> --forms`
- **Parse:** JSON results from output directory
- **Findings:** Confirmed SQL injection points with type and payload

### nuclei (`nuclei.rs`)
- **Binary:** `nuclei`
- **Args:** `-u <target> -json -severity critical,high,medium`
- **Parse:** JSON-lines output (one JSON object per line)
- **Findings:** Template-matched vulnerabilities with severity from nuclei's database

### feroxbuster (`feroxbuster.rs`)
- **Binary:** `feroxbuster`
- **Args:** `-u <target> --json -q`
- **Parse:** JSON-lines output for discovered paths
- **Findings:** Interesting discovered paths (admin panels, config files, etc.)

### sslyze (`sslyze.rs`)
- **Binary:** `sslyze`
- **Args:** `--json_out=- <target>`
- **Parse:** JSON output for SSL/TLS configuration
- **Findings:** Weak ciphers, deprecated protocols, certificate issues
