# External Tools Checklist

ScorchKit wraps external pentesting tools behind a unified interface. Install any tool and it automatically activates on the next scan. Missing tools are skipped gracefully.

Run `scorchkit doctor` (or `scorchkit doctor --deep` for version checks) to see exactly what's present. The authoritative install hints live in `src/cli/doctor.rs::tool_specs()` — this file mirrors them.

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
| Nuclei | `nuclei` | 3.0.0 | `go install github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest` |
| Nikto | `nikto` | 2.1.6 | `sudo apt install nikto` |
| OWASP ZAP | `zap.sh` | 2.14.0 | see [zaproxy.org/download](https://www.zaproxy.org/download/) |
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
| Slither | `slither` | — | `pipx install slither-analyzer` |
| Brakeman | `brakeman` | — | `gem install brakeman` |
| OSV-Scanner | `osv-scanner` | — | `go install github.com/google/osv-scanner/cmd/osv-scanner@latest` |
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
| Trivy | `trivy` | 0.50.0 | see [trivy install guide](https://aquasecurity.github.io/trivy/latest/getting-started/installation/) |
| dockle | `dockle` | — | `brew install goodwithtech/r/dockle` or [releases](https://github.com/goodwithtech/dockle/releases) |
| kubescape | `kubescape` | — | `curl -s https://raw.githubusercontent.com/kubescape/kubescape/master/install.sh \| /bin/bash` |
| Prowler | `prowler` | — | `pip install prowler` |
| Scout Suite | `scout` | — | `pipx install scoutsuite` |

### AI Integration

| Tool | Binary | Min version | Install |
|------|--------|-------------|---------|
| Claude Code | `claude` | — | `npm install -g @anthropic-ai/claude-code` |

## Quick Install (Debian/Ubuntu)

```bash
# apt-installable
sudo apt install -y nmap nikto sqlmap hydra feroxbuster testssl.sh whatweb \
    enum4linux onesixtyone masscan dnsrecon eyewitness

# Go-based (requires Go 1.21+)
for pkg in \
  github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest \
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
  github.com/google/osv-scanner/cmd/osv-scanner@latest \
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

# Rust-based
cargo install feroxbuster cargo-audit cargo-deny

# ZAP + Trivy (via package manager where available)
sudo snap install zaproxy --classic
# or: sudo apt install zaproxy
```

After install, run `scorchkit doctor --deep` to verify versions.

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
