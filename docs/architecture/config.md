# Configuration

The config module (`src/config/`) provides a TOML-based configuration system with sensible defaults. All fields have defaults, so ScorchKit works without any config file.

## Files

```
config/
  mod.rs       Re-exports types.rs
  types.rs     All config structs + loading logic
```

## Config Structs

### AppConfig (top-level)

```rust
pub struct AppConfig {
    pub scan: ScanConfig,
    pub tools: ToolsConfig,
    pub ai: AiConfig,
    pub report: ReportConfig,
}
```

### ScanConfig

Controls HTTP behavior and scan execution.

| Field | Type | Default | Description |
|-------|------|---------|-------------|
| `timeout_seconds` | `u64` | `300` | Global scan timeout |
| `max_concurrent_modules` | `usize` | `4` | Max parallel module execution |
| `user_agent` | `String` | `"ScorchKit/0.1.0"` | HTTP User-Agent header |
| `follow_redirects` | `bool` | `true` | Follow HTTP redirects |
| `max_redirects` | `usize` | `10` | Max redirect chain length |
| `headers` | `HashMap<String, String>` | `{}` | Extra headers on every request |

### ToolsConfig

Path overrides for external tool binaries. All default to `None` (search PATH).

| Field | Type | Default | Description |
|-------|------|---------|-------------|
| `nmap` | `Option<String>` | `None` | Path to nmap binary |
| `nikto` | `Option<String>` | `None` | Path to nikto binary |
| `sqlmap` | `Option<String>` | `None` | Path to sqlmap binary |
| `nuclei` | `Option<String>` | `None` | Path to nuclei binary |
| `feroxbuster` | `Option<String>` | `None` | Path to feroxbuster binary |
| `sslyze` | `Option<String>` | `None` | Path to sslyze binary |
| `testssl` | `Option<String>` | `None` | Path to testssl.sh binary |

### AiConfig

Controls Claude AI integration.

| Field | Type | Default | Description |
|-------|------|---------|-------------|
| `enabled` | `bool` | `true` | Whether AI analysis is available |
| `claude_binary` | `String` | `"claude"` | Path to claude CLI |
| `model` | `String` | `"sonnet"` | Model for analysis |
| `max_budget_usd` | `f64` | `0.50` | Cost cap per analysis run |
| `auto_analyze` | `bool` | `false` | Auto-run AI after scan completes |

### ReportConfig

Controls report output.

| Field | Type | Default | Description |
|-------|------|---------|-------------|
| `output_dir` | `PathBuf` | `"./reports"` | Directory for saved reports |
| `include_evidence` | `bool` | `true` | Include raw evidence in reports |
| `include_remediation` | `bool` | `true` | Include fix suggestions |

## Loading

```rust
AppConfig::load(path: Option<&Path>) -> Result<Self>
```

1. If a path is provided and the file exists, parse it as TOML
2. Missing fields fall back to defaults (via `#[serde(default)]`)
3. If no path or file doesn't exist, return full defaults

The CLI passes `--config` flag value (if provided) to this function.

## Generating Default Config

```rust
AppConfig::default_toml() -> Result<String>
```

Serializes the default config as a TOML string. Used by `scorchkit init`.

## Example config.toml

```toml
[scan]
timeout_seconds = 300
max_concurrent_modules = 4
user_agent = "ScorchKit/0.1.0"
follow_redirects = true
max_redirects = 10

[scan.headers]

[tools]

[ai]
enabled = true
claude_binary = "claude"
model = "sonnet"
max_budget_usd = 0.5
auto_analyze = false

[report]
output_dir = "./reports"
include_evidence = true
include_remediation = true
```

## Adding New Config Fields

1. Add the field to the appropriate struct in `config/types.rs`
2. Add a default value in the struct's `Default` impl
3. Add `#[serde(default)]` on the struct if not already present
4. The field is now available via `ctx.config.<section>.<field>` in any module
