# External Tools Checklist

ScorchKit has built-in modules and optional external-tool adapters. Do not install this complete list
on a normal application-testing host. Start with the binary and the selected workflow, then add only
the tools that workflow needs. Missing tools remain explicit coverage gaps; an installed tool does
not join an implicit profile, widen engagement scope, or grant an effect.

Run `scorchkit doctor --deep` to check presence, executable paths, reviewed versions, and tool-specific
runtime requirements. `src/cli/doctor.rs::tool_specs()` is authoritative; this file mirrors it.

## Recommended application-security layers

| Layer | Install when | Common tools |
|---|---|---|
| Core | Every installation | No external scanner required for built-in checks |
| Fast source | Standard source analysis | Semgrep, Gitleaks, applicable language analyzers |
| Deep source | Thorough source analysis | CodeQL CLI bundle, Psalm, PHPStan |
| Supply chain | Dependency or artifact evidence | Exact OSV Scanner 2.3.8, Syft 1.50.0, Grype 0.116.1, Trivy 0.74.0 |
| Runtime application | Authenticated/schema or template testing | Exact ZAP 2.17.0 and Nuclei 3.11.1 plus their reviewed local inputs |
| Compatibility | Explicit network, enterprise, infrastructure, or cloud work | Only the adapters named in the approved plan and engagement |

## Tool Installation Guide

### Port Scanning & Network

| Tool | Binary | Min version | Install |
|------|--------|-------------|---------|
| Nmap | `nmap` | 7.80 | `sudo apt install nmap` / `brew install nmap` |
| masscan | `masscan` | — | `sudo apt install masscan` or build from [robertdavidgraham/masscan](https://github.com/robertdavidgraham/masscan) |
| naabu | `naabu` | — | `go install github.com/projectdiscovery/naabu/v2/cmd/naabu@latest` |
| smbmap | `smbmap` | — | `pipx install smbmap` (or `pip install smbmap`) |
| NetExec | `nxc` | — | `pipx install git+https://github.com/Pennyw0rth/NetExec` |
| kerbrute | `kerbrute` | — | `go install github.com/ropnop/kerbrute@latest` |
| ssh-audit | `ssh-audit` | — | `pipx install ssh-audit` |
| onesixtyone | `onesixtyone` | — | `sudo apt install onesixtyone` or build from [trailofbits/onesixtyone](https://github.com/trailofbits/onesixtyone) |
| enum4linux | `enum4linux` | — | `sudo apt install enum4linux` |

### Web Vulnerability Scanners

| Tool | Binary | Min version | Install |
|------|--------|-------------|---------|
| Nuclei | `nuclei` | exactly 3.11.1 | install the checksum-verified 3.11.1 release; see [the trusted runtime contract](tools/nuclei.md) |
| Nikto | `nikto` | 2.1.6 | `sudo apt install nikto` |
| OWASP ZAP | `zap.sh` | exactly 2.17.0 | see [the ScorchKit runtime contract](tools/zap.md) |
| WPScan | `wpscan` | 3.8.0 | `gem install wpscan` |
| Droopescan | `droopescan` | — | `pip install droopescan` |
| Wapiti | `wapiti` | — | `pipx install wapiti3` |
| WhatWeb | `whatweb` | — | `sudo apt install whatweb` |

### SQL / Command Injection

| Tool | Binary | Min version | Install |
|------|--------|-------------|---------|
| SQLMap | `sqlmap` | 1.7 | `sudo apt install sqlmap` / `pip install sqlmap` |
| commix | `commix` | — | `pipx install commix` |

### XSS

| Tool | Binary | Min version | Install |
|------|--------|-------------|---------|
| Dalfox | `dalfox` | 2.8.0 | `go install github.com/hahwul/dalfox/v2@latest` |
| XSStrike | `xsstrike` | — | `pipx install xsstrike` |

### Directory / Content Discovery & Fuzzing

| Tool | Binary | Min version | Install |
|------|--------|-------------|---------|
| Feroxbuster | `feroxbuster` | 2.0.0 | `cargo install feroxbuster` |
| ffuf | `ffuf` | 2.0.0 | `go install github.com/ffuf/ffuf/v2@latest` |
| Gobuster | `gobuster` | 3.0.0 | `go install github.com/OJ/gobuster/v3@latest` |
| Arjun | `arjun` | — | `pip install arjun` |
| ParamSpider | `paramspider` | — | `pip install paramspider` |
| CeWL | `cewl` | — | `gem install cewl` |

### TLS / SSL

| Tool | Binary | Min version | Install |
|------|--------|-------------|---------|
| SSLyze | `sslyze` | 5.0.0 | `pip install sslyze` |
| testssl.sh | `testssl.sh` | 3.0 | `git clone https://github.com/drwetter/testssl.sh` |

### DNS / Subdomain / HTTP Probes

| Tool | Binary | Min version | Install |
|------|--------|-------------|---------|
| Amass | `amass` | 4.0.0 | `go install github.com/owasp-amass/amass/v4/...@master` |
| Subfinder | `subfinder` | 2.6.0 | `go install github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest` |
| httpx | `httpx` | 1.3.0 | `go install github.com/projectdiscovery/httpx/cmd/httpx@latest` |
| dnsx | `dnsx` | 1.1.0 | `go install github.com/projectdiscovery/dnsx/cmd/dnsx@latest` |
| DNSRecon | `dnsrecon` | — | `pip install dnsrecon` |

### Crawling / URL Discovery / API

| Tool | Binary | Min version | Install |
|------|--------|-------------|---------|
| Katana | `katana` | 1.0.0 | `go install github.com/projectdiscovery/katana/cmd/katana@latest` |
| gau | `gau` | — | `go install github.com/lc/gau/v2/cmd/gau@latest` |
| Vespasian | `vespasian` | — | `go install github.com/praetorian-inc/vespasian/cmd/vespasian@latest` |
| LinkFinder | `linkfinder` | — | `pipx install linkfinder` |
| EyeWitness | `eyewitness` | — | `sudo apt install eyewitness` |

### OSINT / WAF / Credentials / Exploit

| Tool | Binary | Min version | Install |
|------|--------|-------------|---------|
| theHarvester | `theHarvester` | — | `pip install theHarvester` |
| wafw00f | `wafw00f` | 2.0.0 | `pip install wafw00f` |
| Hydra | `hydra` | 9.0 | `sudo apt install hydra` |
| Metasploit | `msfconsole` | — | see [nightly installer](https://docs.metasploit.com/docs/using-metasploit/getting-started/nightly-installers.html) |
| Interactsh | `interactsh-client` | 1.1.0 | `go install github.com/projectdiscovery/interactsh/cmd/interactsh-client@latest` |

### SAST / SCA / Secrets

| Tool | Binary | Min version | Install |
|------|--------|-------------|---------|
| Semgrep | `semgrep` | 1.0.0 | `pip install semgrep` |
| CodeQL CLI bundle | `codeql` | — | Download the complete bundle from [GitHub](https://github.com/github/codeql-cli-binaries/releases) and review its license |
| PHPStan | `phpstan` | — | `composer global require phpstan/phpstan` |
| Psalm | `psalm` | — | `composer require --dev vimeo/psalm`; expose the project binary on `PATH` |
| Slither | `slither` | — | `pipx install slither-analyzer` |
| Brakeman | `brakeman` | — | `gem install brakeman` |
| OSV Scanner | `osv-scanner` | 2.3.8 exact | Install the `v2.3.8` native release binary and verify its published SHA-256 |
| Syft | `syft` | 1.50.0 exact | Install the `v1.50.0` native release archive and verify its published SHA-256 |
| Grype | `grype` | 0.116.1 exact | Install the `v0.116.1` native release archive and verify its published SHA-256 |
| cargo-audit | `cargo-audit` | — | `cargo install cargo-audit` |
| cargo-deny | `cargo-deny` | — | `cargo install cargo-deny` |
| Gitleaks | `gitleaks` | 8.0.0 | `go install github.com/gitleaks/gitleaks/v8@latest` |
| TruffleHog | `trufflehog` | 3.0.0 | `go install github.com/trufflesecurity/trufflehog/v3@latest` |

### Infrastructure as Code

| Tool | Binary | Min version | Install |
|------|--------|-------------|---------|
| tflint | `tflint` | — | `brew install tflint` or curl-pipe from [terraform-linters/tflint](https://github.com/terraform-linters/tflint) |
| KICS | `kics` | — | `brew install kics` or download from [Checkmarx/kics releases](https://github.com/Checkmarx/kics/releases) |

### Containers & Cloud

| Tool | Binary | Min version | Install |
|------|--------|-------------|---------|
| Trivy | `trivy` | 0.74.0 exact | Install the native `v0.74.0` release archive; Docker/socket wrappers are not accepted |
| dockle | `dockle` | — | `brew install goodwithtech/r/dockle` or [releases](https://github.com/goodwithtech/dockle/releases) |
| kubescape | `kubescape` | — | `curl -s https://raw.githubusercontent.com/kubescape/kubescape/master/install.sh \| /bin/bash` |
| Prowler | `prowler` | — | `pip install prowler` |
| Scout Suite | `scout` | — | `pipx install scoutsuite` |

### AI Integration

| Tool | Binary | Min version | Install |
|------|--------|-------------|---------|
| Codex CLI | `codex` | — | [Official Codex CLI guide](https://developers.openai.com/codex/cli) |
| Claude Code compatibility adapter | `claude` | — | `npm install -g @anthropic-ai/claude-code` |

## Quick Install (Debian/Ubuntu)

```bash
# apt-installable
sudo apt install -y nmap nikto sqlmap hydra feroxbuster testssl.sh whatweb \
    enum4linux onesixtyone masscan dnsrecon eyewitness

# Go-based (requires Go 1.21+)
for pkg in \
  github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest \
  github.com/projectdiscovery/httpx/cmd/httpx@latest \
  github.com/projectdiscovery/dnsx/cmd/dnsx@latest \
  github.com/projectdiscovery/katana/cmd/katana@latest \
  github.com/projectdiscovery/naabu/v2/cmd/naabu@latest \
  github.com/projectdiscovery/interactsh/cmd/interactsh-client@latest \
  github.com/ffuf/ffuf/v2@latest \
  github.com/hahwul/dalfox/v2@latest \
  github.com/owasp-amass/amass/v4/...@master \
  github.com/OJ/gobuster/v3@latest \
  github.com/lc/gau/v2/cmd/gau@latest \
  github.com/trufflesecurity/trufflehog/v3@latest \
  github.com/gitleaks/gitleaks/v8@latest \
  github.com/ropnop/kerbrute@latest \
  github.com/praetorian-inc/vespasian/cmd/vespasian@latest; do
    go install "$pkg"
done

# Python-based (pipx is preferred for CLI tools)
pipx install droopescan arjun paramspider wapiti3 commix xsstrike linkfinder \
    sslyze wafw00f theHarvester smbmap ssh-audit slither-analyzer scoutsuite \
    semgrep prowler

# Ruby-based
gem install wpscan cewl brakeman

# PHP project tools
composer global require phpstan/phpstan
# Install Psalm in the assessed project: composer require --dev vimeo/psalm

# Rust-based
cargo install feroxbuster cargo-audit cargo-deny

# ZAP (supply-chain binaries use the exact native releases below)
sudo snap install zaproxy --classic
# or: sudo apt install zaproxy
```

After install, run `scorchkit doctor --deep` to verify versions.

The ordered application supply-chain service pins the Linux amd64 artifacts below. Verify the
download before installation and retain the release checksum document with provisioning evidence.

| Artifact | SHA-256 |
|---|---|
| `syft_1.50.0_linux_amd64.tar.gz` | `bf7b29ff57f06da30918266a0e1c2885a8f99784798d1bdb1628886aa015d788` |
| `osv-scanner_linux_amd64` 2.3.8 | `bc98e15319ed0d515e3f9235287ba53cdc5535d576d24fd573978ecfe9ab92dc` |
| `grype_0.116.1_linux_amd64.tar.gz` | `0122df7b655981abe547ad3d2190d65551dac6a2bfc80b4dc2a989b5d0587458` |
| `trivy_0.74.0_Linux-64bit.tar.gz` | `2ae6fe3ee734b7fdf11335663e18c75ea12dccc76062f09f164a3b0f8be4371a` |

See [Application supply-chain evidence](architecture/application-supply-chain.md) for the offline
database lifecycle and explicit local-target boundary.

CodeQL is intentionally absent from the bulk installer. Install the complete CLI bundle manually,
review its license, and keep its bundled extractors and query packs together. ScorchKit never
downloads CodeQL packs during a scan.

## Config Path Overrides

If a tool is installed in a non-standard location, override the path in `config.toml`:

```toml
[tools]
nmap = "/opt/nmap/bin/nmap"
sqlmap = "/opt/sqlmap/sqlmap.py"
zap = "/opt/ZAP/zap.sh"
```

## Notes

- **Module IDs** (the strings used in `--modules`/`--skip`) are not always the same as the binary name. Run `scorchkit modules --check-tools` for the canonical mapping.
- **Feature gates**: some wrappers only compile when the matching cargo feature is enabled (`--features infra` for the infra orchestrator, `--features storage` for project/finding/schedule CLIs, `--features mcp` for the MCP server).
- **Doctor is the source of truth.** If this file and `scorchkit doctor` disagree, `doctor` wins — open a PR updating this page.
