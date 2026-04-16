# WhatWeb

Deep web-technology fingerprinter with a large plugin database covering CMSes, frameworks, analytics, JS libraries, and web servers. License: GPL-2.0 (upstream: [urbanadventurer/WhatWeb](https://github.com/urbanadventurer/WhatWeb)).

## Install

```
apt install whatweb    # Debian / Ubuntu
# or: git clone https://github.com/urbanadventurer/WhatWeb
```

Verify with `scorchkit doctor`.

## What ScorchKit surfaces

The wrapper runs `whatweb --log-json=- -q <url>` (quiet + JSON-Lines to stdout) and parses the `plugins` object on each line. All detected plugins are consolidated into a single **Info** finding:

- **Title**: `WhatWeb: technology fingerprint for <url>`
- **Evidence**: joined plugin names (e.g. `Apache, PHP, WordPress, jQuery`)
- **OWASP**: A05:2021 Security Misconfiguration
- **Confidence**: 0.9

The finding is informational — tech disclosure isn't a vulnerability by itself, but it drives downstream decisions (`wpscan` if WordPress is detected, `droopescan` if Drupal, etc.).

## How to run

```
scorchkit run https://target.example.com --modules whatweb
```

60s timeout.

## Limitations vs alternatives

- **vs built-in `tech` recon**: the built-in module uses a small built-in signature table focused on common server / framework headers. WhatWeb's plugin database is orders of magnitude larger (2k+ plugins vs a handful). Run both — cheap recon.
- **vs `httpx`**: httpx is faster and has its own fingerprinting but narrower coverage; WhatWeb has richer CMS/plugin detection. Chain them in large scans: httpx for initial filtering, WhatWeb for depth on survivors.
- Plugin versions captured vary by plugin — some emit exact versions, others only "present". Don't assume version accuracy for CVE matching.
