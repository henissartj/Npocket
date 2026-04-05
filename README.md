# Npocket - Network Exploration & Security Auditing Tool

```text
    _   __                 __        __ 
   / | / /___  ____  _____/ /_____  / /_
  /  |/ / __ \/ __ \/ ___/ //_/ _ \/ __/
 / /|  / /_/ / /_/ / /__/ ,< /  __/ /_  
/_/ |_/ .___/\____/\___/_/|_|\___/\__/  
     /_/                                
```

> **The full power of Nmap, right in your pocket.**

**Npocket** is a highly concurrent, ultra-fast, and modular network scanner built entirely in Python using standard libraries (`asyncio`). It aims to be a modern alternative to Nmap, boasting better performance, built-in intelligent features, and beautiful outputs.

## 🚀 Key Features

- **Ultra-Fast Asynchronous Engine**: Uses `asyncio` to scan thousands of ports in seconds without thread-pool overhead.
- **Smart Adaptive Timing (`--smart`)**: Automatically adjusts timeouts dynamically based on network latency and packet loss.
- **Subdomain Enumeration & DNS Bruteforce (`-sD`)**: Automatically enumerates subdomains for any target domain before scanning them.
- **Intelligent Basic Bruteforce (`-B`)**: Detects open services (like FTP) and attempts common default credentials (`admin:admin`, `root:root`, etc.) to find easy wins immediately.
- **Web Info Grabber**: During service detection (`-sV`), Npocket extracts the HTTP `<title>` and `Server` headers.
- **Basic OS Fingerprinting (`-O`)**: Uses TTL-based heuristics to guess the operating system.
- **Multiple Export Formats**: Export results in JSON (`-oJ`), CSV (`-oC`), Markdown (`-oM`), or a **beautiful Interactive HTML Dashboard (`-oH`)**.
- **Zero External Dependencies**: Built 100% with Python Standard Library.

## 💻 Installation

1. Ensure you have **Python 3.7+** installed.
2. Clone the repository:
   ```bash
   git clone https://github.com/urbanyl/npocket.git
   cd npocket
   ```
3. Run the scanner:
   ```bash
   # On Windows
   py -m cli.main -h
   
   # On Linux/Mac
   python3 -m cli.main -h
   ```

## 🛠️ Usage Examples

**Basic Fast Port Scan (Top 100 ports)**
```bash
py -m cli.main 192.168.1.1
```

**Full Port Scan with Service Detection and OS Fingerprint**
```bash
py -m cli.main 10.0.0.1 -p all -sV -O
```

**Domain Target with Subdomain Enumeration & HTML Report**
```bash
py -m cli.main example.com -sD -p 80,443 -sV -oH dashboard.html
```

**Advanced Mode: Smart Timing + Bruteforce**
```bash
py -m cli.main 192.168.1.1 -p 21,22,80 -sV -B --smart
```

## 📖 CLI Options

```text
📌 General:
  -h, --help            Show this help message and exit.

🎯 Target Specification:
  targets               Target IP, domain, CIDR or range
                        Ex: 192.168.1.1, 10.0.0.0/24, example.com
  -sD, --subdomains     Enumerate subdomains and bruteforce DNS if target is a domain

🚪 Port Specification:
  -p, --ports PORTS     Ports to scan (default: top100)
                        Ex: 80,443,1000-2000, all, top100

🔍 Scan Techniques:
  -sS, --tcp            TCP Connect Scan (default)
  -sU, --udp            UDP Scan
  -sn, --ping-scan      Ping scan only (disables port scan)
  -sV, --service        Service/Version detection on open ports (includes Web Grabber)
  -O, --os-fingerprint  Enable basic OS detection
  -B, --bruteforce      Basic intelligent bruteforce on discovered services (FTP, etc.)

⚡ Performance & Timing:
  -T, --timeout TIMEOUT Connection timeout in seconds (default: 1.5)
  -c, --concurrency N   Number of concurrent async tasks (default: 500)
  --smart               Enable smart adaptive timing (dynamically adjusts timeouts)

📊 Output & Display:
  -v, --verbose         Increase verbosity (debug mode)
  --no-progress         Disable progress bar
  -oJ, --output-json    Export results to JSON format
  -oC, --output-csv     Export results to CSV format
  -oM, --output-md      Export results to Markdown format
  -oH, --output-html    Export results to HTML format (Dashboard)
```

## 🏗️ Architecture

Npocket uses a clean, modular architecture:
- `cli/`: Argument parsing and main entry point.
- `scan/`: Core asynchronous engines (`port_scan.py`, `discover.py`, `service.py`, `subdomain.py`, `bruteforce.py`).
- `parse/`: Input parsers for IPs, CIDRs, ranges, and ports.
- `report/`: Formatters, UI colors, and exporters (JSON/CSV/HTML).
- `utils/`: Logging, Configuration, and Progress bar logic.

## 🤝 Contributing
Contributions, issues, and feature requests are welcome! Feel free to check the issues page.
