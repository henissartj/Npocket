<div align="center">

```
    _   __                 __        __
   / | / /___  ____  _____/ /_____  / /_
  /  |/ / __ \/ __ \/ ___/ //_/ _ \/ __/
 / /|  / /_/ / /_/ / /__/ ,< /  __/ /_
/_/ |_/ .___/\____/\___/_/|_|\___/\__/
     /_/
```

# Npocket — Network Exploration & Security Auditing Tool

**The modern Nmap alternative — async, modular, zero-dependency, and packed with intelligence.**

[![Python 3.8+](https://img.shields.io/badge/python-3.8+-blue.svg)](https://www.python.org/)
[![License: MIT](https://img.shields.io/badge/License-MIT-green.svg)](LICENSE)
[![Dependencies](https://img.shields.io/badge/dependencies-0-brightgreen.svg)]()
[![Platform](https://img.shields.io/badge/platform-Windows%20%7C%20Linux%20%7C%20macOS-lightgrey.svg)]()

</div>

---

## Table of Contents

- [Why Npocket?](#why-npocket)
- [Key Features](#key-features)
- [Installation](#installation)
- [Quick Start](#quick-start)
- [Usage](#usage)
  - [Target Specification](#target-specification)
  - [Port Specification](#port-specification)
  - [Scan Techniques](#scan-techniques)
  - [Enumeration & Attack](#enumeration--attack)
  - [Performance & Timing](#performance--timing)
  - [Output & Reporting](#output--reporting)
- [Interactive Mode](#interactive-mode)
- [Examples](#examples)
- [Output Formats](#output-formats)
- [Architecture](#architecture)
- [Comparison with Nmap](#comparison-with-nmap)
- [Contributing](#contributing)
- [License](#license)

---

## Why Npocket?

Npocket is designed from the ground up to be **the fastest, most feature-rich network scanner you can run with zero external dependencies**. Built entirely on Python's standard library with `asyncio`, it delivers Nmap-class performance and goes beyond with built-in intelligence:

- **No dependencies to install** — works out of the box on any Python 3.8+ environment
- **Async-native** — scans thousands of ports in seconds without thread pool overhead
- **All-in-one** — port scanning, OS detection, service fingerprinting, subdomain enumeration, DNS records, traceroute, brute-forcing, vulnerability checking, and web tech detection
- **Beautiful multi-format reports** — console, JSON, CSV, Markdown, and an interactive HTML dashboard
- **Cross-platform** — Windows, Linux, and macOS

---

## Key Features

### Core Scanning Engine
- ⚡ **Asynchronous TCP Connect Scan** — ultra-fast, concurrent port scanning
- 🌐 **UDP Scanning** — basic UDP port detection
- 🎯 **CIDR & Range Support** — `10.0.0.0/24`, `192.168.1.1-50`, mixed inputs
- 🧠 **Smart Adaptive Timing** — dynamically adjusts timeouts based on network latency
- ⏱ **Rate Limiting** — configurable packets-per-second for stealth

### Discovery & Reconnaissance
- 🔍 **Host Discovery** — ping sweep with automatic TCP fallback
- 🖥 **OS Fingerprinting** — TTL-based heuristic detection (Linux, Windows, Solaris, Cisco, etc.)
- 🌍 **Subdomain Enumeration** — 150+ common subdomains resolved concurrently
- 📡 **DNS Record Enumeration** — A, AAAA, MX, NS, TXT, CNAME, SOA records
- 🗺 **Traceroute** — hop-by-hop route analysis

### Service & Vulnerability Analysis
- 🔌 **Service Detection** — protocol-aware banner grabbing (HTTP, SSH, FTP, SMTP, MySQL, PostgreSQL, Redis, MongoDB, and more)
- 🌐 **Web Technology Fingerprinting** — detects 40+ CMS, frameworks, servers, and security headers
- 🔑 **Multi-Protocol Bruteforce** — FTP, SSH, and HTTP Basic Auth with 20+ default credentials
- 🛡 **Vulnerability Scanner** — banner-based CVE matching (Heartbleed, Drupalgeddon, EternalBlue, and 40+ signatures)
- 📋 **Custom Wordlist Support** — load your own credential pairs for brute-forcing

### Reporting & Output
- 📊 **HTML Dashboard** — self-contained, dark-themed, responsive, with vulnerability highlights
- 📄 **JSON/CSV/Markdown** — machine-parseable formats for CI/CD pipelines
- 🎨 **Colored Console Output** — real-time progress bars and color-coded results
- 📁 **Multi-Format Export** — export all formats at once with `-oA`

### User Experience
- 💬 **Interactive Mode** — guided step-by-step scanning with prompts
- ⌨️ **Graceful Interrupt Handling** — clean exit on Ctrl+C
- 📝 **File Logging** — persistent logs for audit trails
- 🚀 **Zero Dependencies** — pure Python 3.8+ standard library

---

## Installation

### Option 1: Run directly (no install)

```bash
# Clone the repository
git clone https://github.com/urbanyl/npocket.git
cd npocket

# Run on Windows
py -m cli.main --help

# Run on Linux/macOS
python3 -m cli.main --help
```

### Option 2: Install via pip

```bash
pip install npocket

# Or install from source
pip install -e .
```

After pip installation, you can run:

```bash
npocket --help
```

### Option 3: Build executable (PyInstaller)

```bash
pip install pyinstaller
pyinstaller --onefile --name npocket cli/main.py
./dist/npocket --help
```

---

## Quick Start

```bash
# Scan top 100 ports on a single host
npocket 192.168.1.1

# Full scan with service detection, OS fingerprint, and HTML report
npocket 10.0.0.1 -p all -sV -O -oH scan.html

# Domain reconnaissance with subdomains, DNS, and vulnerability check
npocket example.com -sD -D -sV -V -W -oA report

# Aggressive scan with brute-forcing
npocket 192.168.1.0/24 -p 21,22,80,443 -sV -B --smart -oH scan.html

# Interactive guided mode
npocket -i
```

---

## Usage

### Target Specification

| Pattern | Example | Description |
|---------|---------|-------------|
| Single IP | `192.168.1.1` | Scan one host |
| Hostname | `example.com` | Resolves to IP automatically |
| CIDR | `10.0.0.0/24` | Scans all hosts in subnet (254 IPs) |
| Range | `192.168.1.1-50` | Scans IPs 1 through 50 |
| Mixed | `10.0.0.1,192.168.1.0/28` | Comma-separated targets |

### Port Specification

| Pattern | Example | Description |
|---------|---------|-------------|
| Default | *(none)* | Top 100 most common ports |
| Single | `-p 80` | One port |
| Multiple | `-p 80,443,3306` | Comma-separated |
| Range | `-p 1-1000` | Port range |
| All | `-p all` | All 65535 ports |
| Top 1000 | `--top1000` | First 1000 ports |

### Scan Techniques

| Flag | Description |
|------|-------------|
| `-sS` (default) | TCP Connect Scan — completes TCP handshake |
| `-sU` | UDP Scan — sends empty UDP datagrams |
| `-sn` | Ping Scan Only — disables port scanning |
| `-sV` | Service Detection — banner grabbing on open ports |
| `-O` | OS Fingerprinting — TTL-based heuristic |
| `-T` | Traceroute — hop-by-hop path discovery |

### Enumeration & Attack

| Flag | Description |
|------|-------------|
| `-sD` | Subdomain Enumeration — resolves 150+ common subdomains |
| `-D` | DNS Enumeration — A, AAAA, MX, NS, TXT, CNAME, SOA records |
| `-B` | Bruteforce — FTP, SSH, and HTTP Basic Auth |
| `-w FILE` | Custom credentials wordlist (format: `user:pass` per line) |
| `-V` | Vulnerability Check — banner-based CVE matching |
| `-W` | Web Technology Detection — CMS, frameworks, servers |

### Performance & Timing

| Flag | Default | Description |
|------|---------|-------------|
| `-T, --timeout` | `1.5s` | Per-connection timeout |
| `-c, --concurrency` | `500` | Maximum concurrent tasks |
| `--rate-limit` | unlimited | Max packets per second |
| `--smart` | off | Dynamic timeout adjustment |
| `--aggressive` | off | Lower timeout, higher concurrency |
| `--skip-discovery` | off | Treat all targets as active |

### Output & Reporting

| Flag | Description |
|------|-------------|
| `-v` | Verbose/debug output |
| `--no-progress` | Disable progress bar |
| `--log-file FILE` | Write logs to file |
| `-oJ FILE` | Export JSON |
| `-oC FILE` | Export CSV |
| `-oM FILE` | Export Markdown |
| `-oH FILE` | Export HTML Dashboard |
| `-oA FILE` | Export all formats (JSON+CSV+MD+HTML) |

---

## Interactive Mode

```bash
npocket -i
```

Interactive mode guides you through each setting with prompts:

```
[?] Target (IP/domain/CIDR): scanme.nmap.org
[?] Ports [top100/top1000/all/custom]: top1000
[?] Scan type [tcp/udp] (default: tcp): tcp
[?] Service detection? [y/N]: y
[?] OS fingerprinting? [y/N]: y
[?] Subdomain enumeration? [y/N]: y
[?] DNS enumeration? [y/N]: y
[?] Bruteforce common creds? [y/N]: y
[?] Vulnerability check? [y/N]: y
[?] Web tech detection? [y/N]: y
[?] Traceroute? [y/N]: n
[?] Output format [json/csv/md/html/all/none]: html
[?] Output filename: scan_report.html
[?] Concurrency [default: 500]: 1000
[?] Timeout in seconds [default: 1.5]: 2.0
```

---

## Examples

### Basic Scan
```bash
npocket 192.168.1.1
```

### Full Reconnaissance
```bash
npocket example.com -sD -D -p all -sV -O -V -W -oH full_recon.html
```

### Internal Network Audit
```bash
npocket 10.0.0.0/24 -p top1000 -sV -O -B --smart -oA network_audit
```

### Vulnerability Assessment
```bash
npocket 192.168.1.0/28 -p 21,22,80,443,3306,3389,8080 -sV -V -B -W -oH vuln_scan.html
```

### Stealth Scan with Rate Limiting
```bash
npocket target.example.com -p 80,443 -sV --rate-limit 10 -T 3.0
```

### Quick Service Check
```bash
npocket 10.0.0.5 -p 80,443,3306,6379,27017 -sV -W
```

### Full Export
```bash
npocket scanme.nmap.org -p 1-10000 -sV -O -oA scan_results
```

### Web Technology Fingerprinting
```bash
npocket example.com -p 80,443,8080,8443 -sV -W -oH tech_report.html
```

### Subdomain + DNS Enumeration
```bash
npocket example.com -sD -D -p 80,443 -sV -oH dns_recon.html
```

---

## Output Formats

### HTML Dashboard

The HTML report is a **self-contained dashboard** with:
- Dark theme with GitHub-inspired design
- Summary statistics (hosts, open ports, vulnerabilities)
- Color-coded host cards
- Interactive vulnerability sections
- Collapsible DNS records and traceroute data
- Responsive design for mobile viewing

### Console Output

Color-coded, real-time output with:
- Progress bars for discovery and scanning phases
- Color-coded port states (green=open, yellow=filtered, red=closed)
- Vulnerability alerts in red
- Bruteforce success indicators
- Summary table with timing statistics

### JSON

```json
{
  "tool": "Npocket v2.0.0",
  "timestamp": "2026-07-24T15:30:00Z",
  "summary": {
    "total_hosts": 3,
    "total_open_ports": 12
  },
  "hosts": { ... }
}
```

### CSV

```
IP,Hostname,OS,Port,Protocol,State,Service,Bruteforce,Vulnerabilities
10.0.0.1,router.local,Linux,80,tcp,open,HTTP: nginx 1.24.0,,-"
```

---

## Architecture

```
npocket/
├── cli/
│   └── main.py           # CLI entry point, argument parsing, orchestration
├── parse/
│   └── parser.py         # Target/port parsing, validation, domain extraction
├── scan/
│   ├── port_scan.py      # Async TCP/UDP scanning engine with rate limiter
│   ├── discover.py       # Host discovery (ping + TCP fallback)
│   ├── service.py        # Protocol-aware banner grabbing
│   ├── os_fingerprint.py # TTL-based OS detection
│   ├── subdomain.py      # Subdomain enumeration (150+ entries)
│   ├── dns_enum.py       # DNS record enumeration (A, MX, NS, TXT, etc.)
│   ├── bruteforce.py     # Multi-protocol credential brute-forcing
│   ├── tech_detect.py    # Web technology fingerprinting
│   ├── traceroute.py     # Hop-by-hop route tracing
│   └── vuln_check.py     # Banner-based CVE vulnerability matching
├── report/
│   ├── formatter.py      # Console output, colored formatting
│   └── exporter.py       # JSON, CSV, Markdown, HTML export
├── utils/
│   ├── config.py         # Global configuration singleton
│   ├── logger.py         # Logging setup (console + file)
│   └── ui.py             # ANSI colors, progress bars, spinner
└── tests/
    ├── test_parser.py    # Parser tests
    ├── test_scan.py      # Scan engine tests
    └── test_utils.py     # Utility tests
```

### Execution Flow

```
    User Input (CLI or Interactive)
              │
              ▼
    ┌──────────────────────┐
    │   parse/parser.py    │  Targets, ports, validation
    └──────────┬───────────┘
               │
    ┌──────────▼───────────┐
    │  scan/subdomain.py   │  Optional: subdomain enumeration
    │  scan/dns_enum.py    │  Optional: DNS records
    └──────────┬───────────┘
               │
    ┌──────────▼───────────┐
    │  scan/discover.py    │  Host discovery (ping/TCP)
    └──────────┬───────────┘
               │
    ┌──────────▼───────────┐
    │ scan/os_fingerprint  │  Optional: OS detection
    └──────────┬───────────┘
               │
    ┌──────────▼───────────┐
    │  scan/port_scan.py   │  TCP/UDP port scanning
    │  scan/service.py     │  Banner grabbing
    └──────────┬───────────┘
               │
    ┌──────────▼───────────┐
    │  scan/bruteforce.py  │  Optional: credential brute-force
    │  scan/vuln_check.py  │  Optional: vulnerability check
    │  scan/tech_detect.py │  Optional: web tech detection
    │  scan/traceroute.py  │  Optional: route tracing
    └──────────┬───────────┘
               │
    ┌──────────▼───────────┐
    │    report/           │  Console + file export
    │  formatter.py        │  (JSON, CSV, MD, HTML)
    │  exporter.py         │
    └──────────────────────┘
```

---

## Comparison with Nmap

| Feature | Npocket | Nmap | Notes |
|---------|---------|------|-------|
| **Dependencies** | Zero (stdlib) | None (C compiled) | Both are dependency-free |
| **Install Size** | ~1 MB | ~30 MB | Npocket is purely Python |
| **TCP Connect Scan** | ✅ | ✅ | Both async-capable |
| **SYN Stealth Scan** | ❌ | ✅ | Requires raw sockets (Npocket uses connect) |
| **UDP Scan** | ✅ | ✅ | Both limited without raw sockets |
| **Service Detection** | ✅ | ✅ | Nmap has larger DB, Npocket adds web tech |
| **OS Detection** | ✅ TTL-based | ✅ (advanced fingerprint DB) | Nmap is more accurate |
| **Subdomain Enum** | ✅ Built-in | ❌ (via scripts) | Npocket has 150+ built-in |
| **DNS Enumeration** | ✅ Built-in | ❌ (via scripts) | A, MX, NS, TXT, CNAME, SOA |
| **Bruteforce** | ✅ FTP/SSH/HTTP | ❌ (via scripts) | Npocket has built-in creds |
| **Vuln Detection** | ✅ Banner-based | ❌ (via scripts + NSE) | Npocket has 40+ signatures |
| **Web Tech Detection** | ✅ 40+ patterns | ❌ (via scripts) | Built-in fingerprinting |
| **Traceroute** | ✅ Basic | ✅ Advanced | Both functional |
| **Interactive Mode** | ✅ | ❌ | Guided step-by-step |
| **HTML Reports** | ✅ Dashboard | ✅ (via option) | Both produce HTML |
| **Scriptable/Extensible** | ✅ Modular | ✅ NSE | Both extensible |
| **Cross-Platform** | ✅ Python | ✅ | Npocket easier on Windows |
| **Python API** | ✅ Importable | ❌ | Use as library |

> **Bottom line:** Nmap is the gold standard for deep packet-level analysis and has a massive community. Npocket excels where you need zero dependencies, built-in intelligence (subdomains, DNS, brute-force, vuln check), beautiful HTML reports, and Python integrations — all out of the box with a single `pip install`.

---

## Performance Tips

- **Increase concurrency** with `-c 1000` for fast networks, lower to `-c 100` for stability
- **Use `--smart`** on varying-latency networks to dynamically optimize timeouts
- **Use `--aggressive`** for internal network scans where speed matters
- **Use `--rate-limit 100`** to avoid detection or network congestion
- **Use `--skip-discovery`** if you know hosts are up (saves one round trip)
- **Narrow your port range** with `-p top1000` instead of `-p all` for faster results
- **Use `-oA`** to export all formats at once without re-running the scan

---

## Testing

```bash
# Install test dependencies
pip install pytest pytest-asyncio

# Run tests
pytest tests/

# Run with coverage
pip install pytest-cov
pytest --cov=cli --cov=parse --cov=scan --cov=report --cov=utils tests/
```

---

## Contributing

Contributions are welcome! Here's how to get started:

1. Fork the repository
2. Create a feature branch: `git checkout -b feature/my-feature`
3. Commit your changes: `git commit -am 'Add my feature'`
4. Push to the branch: `git push origin feature/my-feature`
5. Open a Pull Request

### Development Guidelines

- Follow existing code style (PEP 8, type hints)
- Add tests for new functionality
- Keep zero external dependencies — stdlib only
- Update the README for new features
- Run `pytest tests/` before submitting

---

## Roadmap

- [ ] SYN stealth scan (requires raw socket / Scapy integration)
- [ ] Service version database expansion (200+ signatures)
- [ ] SNMP enumeration
- [ ] Web crawler integration
- [ ] Real-time dashboard (WebSocket-based)
- [ ] Docker image
- [ ] CI/CD pipeline integration
- [ ] Plugin system for custom scanners

---

## License

MIT License — see [LICENSE](LICENSE) for details.

---

<div align="center">
  Made with ⚡ by <a href="https://github.com/urbanyl">Fazer</a>
  <br>
  <a href="https://github.com/urbanyl/npocket/issues">Report Bug</a>
  ·
  <a href="https://github.com/urbanyl/npocket/issues">Request Feature</a>
</div>