# External Tools Checklist

ScorchKit wraps external pentesting tools behind a unified interface. Install any tool and it automatically activates on the next scan. Missing tools are skipped gracefully.

Run `scorchkit doctor` to check which tools are installed.

## Tool Installation Guide

### Port Scanning & Network

| Tool | Module ID | Install |
|------|-----------|---------|
| nmap | `nmap` | `sudo apt install nmap` / `brew install nmap` |
| masscan | — | `sudo apt install masscan` / `brew install masscan` |

### Web Vulnerability Scanners

| Tool | Module ID | Install |
|------|-----------|---------|
| nuclei | `nuclei` | `go install github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest` |
| nikto | `nikto` | `sudo apt install nikto` / `brew install nikto` |
| ZAP | `zap` | `sudo apt install zaproxy` / `brew install --cask zap` or [download](https://www.zaproxy.org/download/) |
| WPScan | `wpscan` | `gem install wpscan` / `docker pull wpscanteam/wpscan` |
| Droopescan | `droopescan` | `pip install droopescan` |

### SQL Injection

| Tool | Module ID | Install |
|------|-----------|---------|
| sqlmap | `sqlmap` | `sudo apt install sqlmap` / `pip install sqlmap` |

### XSS Detection

| Tool | Module ID | Install |
|------|-----------|---------|
| Dalfox | `dalfox` | `go install github.com/hahwul/dalfox/v2@latest` |

### Directory / Content Discovery

| Tool | Module ID | Install |
|------|-----------|---------|
| feroxbuster | `feroxbuster` | `sudo apt install feroxbuster` / `cargo install feroxbuster` |
| ffuf | `ffuf` | `go install github.com/ffuf/ffuf/v2@latest` / `sudo apt install ffuf` |
| Gobuster | `gobuster` | `go install github.com/OJ/gobuster/v3@latest` / `sudo apt install gobuster` |

### Fuzzing & Parameter Discovery

| Tool | Module ID | Install |
|------|-----------|---------|
| Arjun | `arjun` | `pip install arjun` |
| CeWL | `cewl` | `sudo apt install cewl` / `gem install cewl` |
| ParamSpider | `paramspider` | `pip install paramspider` |

### TLS/SSL Analysis

| Tool | Module ID | Install |
|------|-----------|---------|
| sslyze | `sslyze` | `pip install sslyze` |
| testssl.sh | `testssl` | `sudo apt install testssl.sh` / `brew install testssl` / `git clone https://github.com/drwetter/testssl.sh` |

### DNS Enumeration

| Tool | Module ID | Install |
|------|-----------|---------|
| dnsrecon | `dnsrecon` | `sudo apt install dnsrecon` / `pip install dnsrecon` |
| DNSx | `dnsx` | `go install github.com/projectdiscovery/dnsx/cmd/dnsx@latest` |

### Subdomain Enumeration

| Tool | Module ID | Install |
|------|-----------|---------|
| Amass | `amass` | `go install github.com/owasp-amass/amass/v4/...@master` / `sudo apt install amass` |
| Subfinder | `subfinder` | `go install github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest` |

### HTTP Probing

| Tool | Module ID | Install |
|------|-----------|---------|
| httpx | `httpx` | `go install github.com/projectdiscovery/httpx/cmd/httpx@latest` |

### Web Crawling

| Tool | Module ID | Install |
|------|-----------|---------|
| Katana | `katana` | `go install github.com/projectdiscovery/katana/cmd/katana@latest` |

### Passive URL Discovery

| Tool | Module ID | Install |
|------|-----------|---------|
| Gau | `gau` | `go install github.com/lc/gau/v2/cmd/gau@latest` |

### OSINT

| Tool | Module ID | Install |
|------|-----------|---------|
| theHarvester | `theharvester` | `pip install theHarvester` / `sudo apt install theharvester` |

### WAF Detection

| Tool | Module ID | Install |
|------|-----------|---------|
| wafw00f | `wafw00f` | `pip install wafw00f` |

### SMB Enumeration

| Tool | Module ID | Install |
|------|-----------|---------|
| enum4linux | `enum4linux` | `sudo apt install enum4linux` |

### Out-of-Band Detection

| Tool | Module ID | Install |
|------|-----------|---------|
| Interactsh | `interactsh` | `go install github.com/projectdiscovery/interactsh/cmd/interactsh-client@latest` |

### Credential Testing

| Tool | Module ID | Install |
|------|-----------|---------|
| Hydra | `hydra` | `sudo apt install hydra` / `brew install hydra` |

### Exploit Frameworks

| Tool | Module ID | Install |
|------|-----------|---------|
| Metasploit | `metasploit` | `curl https://raw.githubusercontent.com/rapid7/metasploit-omnibus/master/config/templates/metasploit-framework-wrappers/msfupdate.erb > msfinstall && chmod 755 msfinstall && ./msfinstall` |

### Cloud Security

| Tool | Module ID | Install |
|------|-----------|---------|
| Prowler | `prowler` | `pip install prowler` / `brew install prowler` |

### Container & Dependency Scanning

| Tool | Module ID | Install |
|------|-----------|---------|
| Trivy | `trivy` | `sudo apt install trivy` / `brew install trivy` |

### Secret Scanning

| Tool | Module ID | Install |
|------|-----------|---------|
| Trufflehog | `trufflehog` | `go install github.com/trufflesecurity/trufflehog/v3@latest` / `brew install trufflehog` |

## Quick Install (Debian/Ubuntu)

```bash
# Core tools
sudo apt install -y nmap nikto sqlmap hydra sslyze feroxbuster testssl.sh wafw00f theharvester cewl gobuster dnsrecon enum4linux trivy

# Go-based tools (requires Go 1.21+)
go install github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest
go install github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest
go install github.com/projectdiscovery/httpx/cmd/httpx@latest
go install github.com/projectdiscovery/dnsx/cmd/dnsx@latest
go install github.com/projectdiscovery/katana/cmd/katana@latest
go install github.com/projectdiscovery/interactsh/cmd/interactsh-client@latest
go install github.com/ffuf/ffuf/v2@latest
go install github.com/hahwul/dalfox/v2@latest
go install github.com/owasp-amass/amass/v4/...@master
go install github.com/OJ/gobuster/v3@latest
go install github.com/lc/gau/v2/cmd/gau@latest
go install github.com/trufflesecurity/trufflehog/v3@latest

# Python-based tools
pip install droopescan arjun paramspider prowler

# Ruby-based tools
gem install wpscan

# ZAP
sudo apt install zaproxy
```

## Config Path Overrides

If a tool is installed in a non-standard location, override the path in `config.toml`:

```toml
[tools]
nmap = "/opt/nmap/bin/nmap"
sqlmap = "/opt/sqlmap/sqlmap.py"
zap = "/opt/ZAP/zap.sh"
```
