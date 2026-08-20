# External Tool Wrappers

URL-targeted wrappers live in `src/tools/` and implement `ScanModule`. Code-targeted wrappers live
in `src/sast_tools/` and implement `CodeModule`. Both families declare their external executable
and delegate execution to a policy-sealed context.

## Files

```
tools/
  mod.rs           Module declarations and registration (46 wrappers)
  amass.rs         OWASP Amass subdomain enumeration
  arjun.rs         Hidden HTTP parameter discovery
  cewl.rs          Custom wordlist generation
  dalfox.rs        Advanced XSS scanning
  dnsrecon.rs      Comprehensive DNS enumeration
  dnsx.rs          Fast DNS resolution and record queries
  droopescan.rs    CMS vulnerability scanning
  enum4linux.rs    SMB share and user enumeration
  feroxbuster.rs   Recursive directory discovery
  ffuf.rs          Fast content discovery and fuzzing
  gau.rs           Passive URL discovery
  gobuster.rs      Directory and vhost brute-forcing
  httpx.rs         HTTP technology probing
  hydra.rs         Default credential testing
  interactsh.rs    Out-of-band callback detection
  katana.rs        JS-rendering web crawler
  metasploit.rs    Exploit validation via auxiliary modules
  nikto.rs         Web server vulnerability scanning
  nmap.rs          Port scanning and service detection
  nuclei.rs        Template-based vulnerability scanning
  paramspider.rs   URL parameter mining
  prowler.rs       Cloud infrastructure security assessment
  sqlmap.rs        Automated SQL injection detection
  sslyze.rs        TLS/SSL configuration analysis
  subfinder.rs     Passive subdomain discovery
  testssl.rs       Comprehensive TLS/SSL testing
  theharvester.rs  Email and subdomain harvesting
  trivy.rs         Container and dependency vulnerability scanning
  trufflehog.rs    Secret scanning for credentials
  wafw00f.rs       WAF detection
  wpscan.rs        WordPress vulnerability scanning
  zap.rs           Active web application scanning
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

        // 2. Run the tool through the context-owned executor
        let output = ctx.run_tool(
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

1. Calls `module.requires_external_tool()` -> `true`
2. Calls `module.required_tool()` -> `Some("nmap")`
3. Runs `which nmap` to check availability
4. If not found: skips module, records `("nmap", "external tool 'nmap' not found")` in `modules_skipped`
5. If found: runs the module normally

This means tool wrappers are zero-cost if the tool isn't installed. Users see them in `scorchkit modules --check-tools` and can install as needed.

## Subprocess API

All bounded wrappers use the executor carried by `ScanContext`:

```rust
pub async fn ScanContext::run_tool(
    tool_name: &str,   // Binary name or path
    args: &[&str],     // Command arguments
    timeout: Duration, // Max execution time
) -> Result<ToolOutput>
```

Returns bounded `ToolOutput { stdout, stderr, exit_code, duration, resolved_program }` on success.
The executor records the canonical binary path, enforces a timeout, caps stdout and stderr at 8 MiB,
and kills the child when the timeout expires. Interactsh uses a separate long-lived session manager.

## Code analyzer depth and artifacts

Code descriptors add a `fast` or `deep` analysis depth. The standard profile selects fast
application analyzers. Thorough and pentest add deep analyzers. Explicit module IDs remain eligible
under any valid profile.

`CodeContext::run_invocation` is the owned multi-step form of the same bounded process boundary.
CodeQL uses it for a no-build database-create step followed by offline SARIF analysis. Psalm uses it
for a PHP taint-analysis SARIF report. Each run owns a private temporary directory, reads reports
through a 64 MiB limit, rejects symlinked reports, and removes its artifacts when the module returns.
Semgrep materializes its embedded rule pack as an owned temporary file and records the pack digest.

`ScanResult` records typed module outcomes in addition to the legacy run/skipped lists. Missing
tools, unsupported languages, valid runs, and execution/parser failures therefore remain distinct.

## Tool Path Override

Users can override tool binary paths in `config.toml`:

```toml
[tools]
nmap = "/usr/local/bin/nmap"
sqlmap = "/opt/sqlmap/sqlmap.py"
```

When implementing a wrapper, check `ctx.config.tools.<tool>` for a custom path before falling back to the binary name.

## Tool Wrapper Reference

### Reconnaissance & Discovery

| ID | Name | Binary | Description |
|----|------|--------|-------------|
| `amass` | Amass Subdomain Enumerator | `amass` | Advanced subdomain enumeration via OWASP Amass |
| `subfinder` | Subfinder | `subfinder` | Fast passive subdomain discovery via Subfinder |
| `theharvester` | theHarvester OSINT | `theharvester` | Email and subdomain harvesting via theHarvester |
| `httpx` | httpx HTTP Prober | `httpx` | HTTP technology probing via httpx |
| `katana` | Katana Web Crawler | `katana` | JS-rendering web crawler for comprehensive endpoint discovery |
| `gau` | Gau Passive URLs | `gau` | Passive URL discovery from Wayback Machine, Common Crawl, and other sources |
| `paramspider` | ParamSpider | `paramspider` | Mine URLs with query parameters for injection point discovery |
| `arjun` | Arjun Parameter Discovery | `arjun` | Hidden HTTP parameter discovery via Arjun |
| `cewl` | CeWL Wordlist Generator | `cewl` | Custom wordlist generation from target content via CeWL |

### Directory & Content Discovery

| ID | Name | Binary | Description |
|----|------|--------|-------------|
| `feroxbuster` | Feroxbuster Directory Scanner | `feroxbuster` | Recursive directory and content discovery via feroxbuster |
| `ffuf` | ffuf Web Fuzzer | `ffuf` | Fast content discovery and fuzzing via ffuf |
| `gobuster` | Gobuster Directory Scanner | `gobuster` | Directory and vhost brute-forcing via Gobuster |
| `nikto` | Nikto Web Scanner | `nikto` | Web server vulnerability scanning via nikto |

### DNS

| ID | Name | Binary | Description |
|----|------|--------|-------------|
| `dnsrecon` | dnsrecon DNS Enumerator | `dnsrecon` | Comprehensive DNS enumeration: zone transfers, reverse lookups, SRV records via dnsrecon |
| `dnsx` | DNSx DNS Toolkit | `dnsx` | Fast DNS resolution, wildcard detection, and record queries via DNSx |

### Vulnerability Scanning

| ID | Name | Binary | Description |
|----|------|--------|-------------|
| `nuclei` | Nuclei Template Scanner | `nuclei` | Template-based vulnerability scanning via nuclei |
| `sqlmap` | SQLMap Injection Scanner | `sqlmap` | Automated SQL injection detection via sqlmap |
| `dalfox` | Dalfox XSS Scanner | `dalfox` | Advanced XSS scanning via Dalfox |
| `nmap` | Nmap Port Scanner | `nmap` | Port scanning and service detection via nmap |
| `zap` | OWASP ZAP | `zap-cli` | Active web application scanning via OWASP ZAP |
| `metasploit` | Metasploit Scanner | `msfconsole` | Exploit validation via Metasploit auxiliary modules |
| `interactsh` | Interactsh OOB Detection | `interactsh-client` | Detect blind SSRF, XXE, RCE, and SQLi via out-of-band callbacks |

### TLS/SSL

| ID | Name | Binary | Description |
|----|------|--------|-------------|
| `sslyze` | SSLyze TLS Analyzer | `sslyze` | Comprehensive TLS/SSL configuration analysis via sslyze |
| `testssl` | testssl.sh TLS Analyzer | `testssl.sh` | Comprehensive TLS/SSL testing via testssl.sh |

### CMS & Application-Specific

| ID | Name | Binary | Description |
|----|------|--------|-------------|
| `wpscan` | WPScan WordPress Scanner | `wpscan` | WordPress vulnerability scanning via WPScan |
| `droopescan` | Droopescan CMS Scanner | `droopescan` | CMS vulnerability scanning (Drupal, Joomla, WordPress, Silverstripe) |

### Authentication

| ID | Name | Binary | Description |
|----|------|--------|-------------|
| `hydra` | Hydra Login Tester | `hydra` | Default credential testing via Hydra |

### WAF Detection

| ID | Name | Binary | Description |
|----|------|--------|-------------|
| `wafw00f` | WAF Detection (wafw00f) | `wafw00f` | Web Application Firewall detection via wafw00f |

### Secret Scanning

| ID | Name | Binary | Description |
|----|------|--------|-------------|
| `trufflehog` | Trufflehog Secret Scanner | `trufflehog` | Secret scanning for API keys, credentials, and tokens via Trufflehog |

### Infrastructure & Cloud

| ID | Name | Binary | Description |
|----|------|--------|-------------|
| `prowler` | Prowler Cloud Scanner | `prowler` | Cloud infrastructure security assessment via Prowler (AWS, Azure, GCP) |
| `trivy` | Trivy Vulnerability Scanner | `trivy` | Container image and dependency vulnerability scanning via Trivy |
| `enum4linux` | enum4linux SMB Enumerator | `enum4linux` | SMB share, user, group, and password policy enumeration via enum4linux |
