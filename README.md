# Reconnaissance Toolkit v2.0

**Production-Grade Network Reconnaissance Suite**  
**62/62 Tests Passing · 8 CLI Subcommands · Interactive Menu · wifi_down-Style Launch**

---

## Quick Overview

| Component | Status | Details |
|-----------|--------|---------|
| **Launch Banner** | ✅ New | wifi\_down-style — scan-line art, typewriter, hacker quote, ENTER prompt |
| **Interactive Menu** | ✅ Ready | `tools/recon_menu.py` — full menu-driven interface |
| **CLI** | ✅ Ready | Typer-based with 8 subcommands via `recon.py` |
| **Tests** | ✅ 62/62 | Config, DNS, ports, vulns, output |
| **Modules** | ✅ 7 | DNS, host discovery, OS, ports, vulns, wireless, PCAP |
| **CVE Database** | ✅ 55 | Apache, SSH, Log4j, Exchange, F5, Citrix, VMware… |
| **Service Probes** | ✅ 35+ | HTTP, SSH, Redis, ES, Docker, K8s… |
| **Default Creds** | ✅ 13 | FTP, SSH, HTTP, Redis, MySQL, MongoDB… |

---

## Table of Contents

1. [Installation](#installation)
2. [Quick Start](#quick-start)
3. [Banner & Launch Experience](#banner--launch-experience)
4. [Interactive Menu](#interactive-menu)
5. [CLI Reference](#cli-reference)
6. [Modules Overview](#modules-overview)
7. [Output Formats](#output-formats)
8. [Project Structure](#project-structure)
9. [Examples](#examples)
10. [Testing](#testing)
11. [Legal Notice](#legal-notice)

---

## Installation

### Prerequisites
- **Python 3.12+**
- **pip** or similar package manager
- **Linux/macOS** recommended (Windows: limited raw-socket features)

### Install Dependencies

```bash
# Core requirements
pip install -r requirements.txt

# Optional: raw socket scanning (Scapy)
pip install scapy

# Optional: packet manipulation
pip install cryptography>=41.0.0
```

### Verify Installation

```bash
python recon.py privcheck
python recon.py --help
```

---

## Quick Start

### Interactive Menu (recommended)

```bash
python tools/recon_menu.py
```

Full wifi\_down-style launch banner plays once on startup, then drops you into the interactive menu.

### CLI Mode

```bash
python recon.py dns -d target.com --full
python recon.py discover -t 192.168.1.0/24 --tcp --icmp
python recon.py portscan -t 192.168.1.100 -s connect -p top1000
python recon.py os -t 192.168.1.100
python recon.py vulnscan -t 192.168.1.100 --all
python recon.py full -t 192.168.1.100 --out ./report
python recon.py privcheck
pytest recon/tests/ -v
```

---

## Banner & Launch Experience

The banner system is modelled directly on [wifi\_down](https://github.com/amibhai/wifi_down).

### Launch sequence (runs once at startup)

```
1.  cls / clear screen
2.  RECON block-art — revealed row-by-row with 0.04 s scan-line delay
    Tri-zone colour gradient: cyan (51) → azure bold (87) → teal (50)
    Corner box-chars highlighted in colour(45)
3.  ── made by Swastik ──   typed char-by-char at 0.04 s/char
4.  Random hacker quote     typewriter with ❝❞ delimiters
5.  Legal notice            plain typewriter, no panel
6.  Status bar              ◈ toolkit: recon v2.0  ◈ status: ready  ◈ <time>
7.  [ Press ENTER to launch recon-toolkit ]
    → 3-cycle colour pulse (51 → 87 → 123 → 87 → 51)
    → waits for ENTER, then clears screen
```

### Compact header (shown at top of every menu screen)

```
  recon-toolkit  ◈  2026-06-12  00:04:11  ◈  <target>
```

### Programmatic use

```python
from recon.core.logger import print_banner, print_compact_header

print_banner()               # full launch sequence (call once)
print_compact_header(target) # one-liner for repeated screens
```

---

## Interactive Menu

Run with:

```bash
python tools/recon_menu.py
```

```
  recon-toolkit  ◈  2026-06-12  00:15:32

  RECONNAISSANCE TOOLS

  1.  DNS Enumeration      zone transfer · records · subdomain brute
  2.  Host Discovery       ARP · ICMP · TCP · UDP
  3.  OS Scan              TTL · TCP stack · banners · ICMP quirks
  4.  Ping Sweep           threaded ICMP/TCP with evasion options
  5.  Port Scan            SYN/Connect/FIN/XMAS/ACK/UDP + services
  6.  Vulnerability Scan   CVE DB · SSL audit · default creds
  7.  Wireless Adapter     monitor mode · channel hopping

  P.  PCAP Settings        ○ capture OFF
  0.  Exit
```

### PCAP capture

Toggle inline PCAP capture from the **P** menu. When enabled, every scan session writes a timestamped `.pcap` file to the configured directory:

```
DNS_Enumeration_20260612_001532.pcap
Port_Scan_20260612_001600.pcap
```

---

## CLI Reference

### Core Subcommands

| Command | Purpose | Requires Root? |
|---------|---------|----------------|
| `dns` | DNS enumeration (AXFR, wildcards, brute-force) | No |
| `discover` | Host discovery (ARP, ICMP, TCP, UDP) | Some |
| `os` | OS fingerprinting (TCP stack, TTL, banners) | Some |
| `portscan` | Port scanning (SYN, Connect, UDP) | Some |
| `vulnscan` | Vulnerability assessment (CVE, SSL, creds) | No |
| `wireless` | 802.11 monitoring & packet capture | Yes |
| `full` | Full pipeline with HTML report | Some |
| `privcheck` | Show privilege status | No |

### Command Details

#### **dns** — DNS Enumeration

```bash
python recon.py dns -d example.com [OPTIONS]

Options:
  --full              Run all DNS methods
  --zone              Zone transfer detection only
  --brute             Subdomain brute-force
  --reverse CIDR      Reverse DNS sweep
  -w, --wordlist FILE Custom subdomain wordlist
  --threads N         Thread count (default: 50)
  --timeout SECONDS   Per-query timeout (default: 3.0)
  -o, --output-dir    Output directory (default: ./output)
```

```bash
python recon.py dns -d target.com --full --threads 20
```

---

#### **discover** — Host Discovery

```bash
python recon.py discover -t 192.168.1.0/24 [OPTIONS]

Options:
  --arp               ARP sweep (Layer 2, root required)
  --icmp              ICMP echo sweep
  --tcp               TCP connect sweep
  --udp               UDP probe sweep
  --all               All methods combined
  --threads N         Thread count (default: 100)
  --timeout SECONDS   Per-host timeout (default: 2.0)
```

```bash
python recon.py discover -t 10.0.0.0/24 --tcp --icmp --threads 100
```

---

#### **os** — OS Fingerprinting

```bash
python recon.py os -t 192.168.1.100 [OPTIONS]

Options:
  --full              All methods combined
  --ttl               TTL-based detection (no root)
  --banner            Banner grabbing on common ports
  --tcp-stack         TCP stack analysis (root required)
  --timeout SECONDS   Connection timeout (default: 3.0)
```

```bash
python recon.py os -t 192.168.1.100 --full
```

---

#### **portscan** — Port Scanning

```bash
python recon.py portscan -t 192.168.1.100 [OPTIONS]

Options:
  -s, --scan {syn,connect,fin,xmas,null,ack,maimon,udp}
                      Scan technique (default: syn)
  -p, --ports {top100,top1000,all,1-1024,80,443}
                      Port selection (default: top1000)
  --no-service        Skip service/version detection
  --threads N         Thread count (default: 50)
  --timeout SECONDS   Per-port timeout (default: 3.0)
  --evasion 0-3       Evasion level (0=off, 3=max)
```

```bash
python recon.py portscan -t 192.168.1.100 -s connect -p top1000
sudo python recon.py portscan -t 192.168.1.100 -s syn -p all --evasion 2
```

---

#### **vulnscan** — Vulnerability Assessment

```bash
python recon.py vulnscan -t 192.168.1.100 [OPTIONS]

Options:
  --all               All checks (CVE + SSL + creds + misconfigs)
  --cve               Banner-to-CVE matching
  --ssl               SSL/TLS certificate and cipher audit
  --creds             Default credential tests
  --misconfig         Misconfiguration detection
  -p, --ports PORTS   Custom port list (auto-scans top 100 if omitted)
```

```bash
python recon.py vulnscan -t 192.168.1.100 --all
python recon.py vulnscan -t 192.168.1.100 --cve --ssl --ports 22,80,443,6379
```

---

#### **wireless** — Wireless Reconnaissance

```bash
python recon.py wireless [OPTIONS]

Options:
  --list              List wireless adapters
  --monitor IF        Enable monitor mode on interface
  --restore IF        Restore interface to managed mode
  --scan              Capture and display nearby networks
  -i, --iface IF      Interface for scan
  --duration SECS     Capture duration (default: 30)
  --bands             Frequency bands (default: 2.4ghz,5ghz)
```

```bash
sudo python recon.py wireless --list
sudo python recon.py wireless --scan -i wlan0 --duration 60
```

---

#### **full** — Full Pipeline with Report

```bash
python recon.py full -t 192.168.1.100 [OPTIONS]

Options:
  -o, --out DIR       Output directory (default: ./output)
  --threads N         Thread count (default: 50)
  --timeout SECONDS   Timeout (default: 3.0)
  --evasion 0-3       Evasion level
  --pcap              Enable PCAP capture during scan
  --open / --no-open  Auto-open HTML report (default: open)
```

Pipeline stages: discover → OS fingerprint → port scan → vuln scan → HTML report.

```bash
python recon.py full -t 192.168.1.100 --out ./results
```

---

#### **privcheck** — Privilege Status

```bash
python recon.py privcheck
```

Shows current user, effective UID, Scapy availability, and which scan types are accessible without root.

---

## Modules Overview

| Module | Purpose | Key Features |
|--------|---------|--------------|
| `dns_enum.py` | DNS Enumeration | AXFR, wildcards, brute-force, DNSSEC |
| `host_discovery.py` | Host Discovery | ARP, ICMP, TCP, UDP with OUI lookup |
| `os_fingerprint.py` | OS Fingerprinting | 15 signatures, TTL, banners, ICMP quirks |
| `port_scan.py` | Port Scanning | SYN/Connect/FIN/XMAS/NULL/ACK/UDP, evasion |
| `vuln_scan.py` | Vulnerability Scan | 55 CVEs, SSL audit, default creds, misconfigs |
| `wireless.py` | Wireless Recon | Monitor mode, channel hopping, 802.11 parsing |
| `pcap_capture.py` | PCAP Capture | AsyncSniffer, ring-buffer, thread-safe |

---

## Output Formats

### JSON

```bash
python recon.py portscan -t 192.168.1.100 -o ./output
```

```json
{
  "target": "192.168.1.100",
  "scan_type": "portscan",
  "start_time": "2026-06-12T00:15:32Z",
  "hosts": [...],
  "findings": [...]
}
```

### HTML Report

Generated by `recon.py full` — dark theme, sortable tables, severity badges, auto-opens in browser.

### PCAP

Packet captures written during any scan:

```python
from scapy.all import rdpcap
packets = rdpcap('Port_Scan_20260612_001532.pcap')
```

---

## Project Structure

```
recon-toolkit/
├── recon.py                    # Typer CLI entry point (8 subcommands)
├── requirements.txt
├── README.md
├── CHANGELOG.md
│
├── tools/
│   └── recon_menu.py           # Interactive menu (wifi_down-style launch)
│
├── recon/
│   ├── core/
│   │   ├── logger.py           # Banner system + Rich logger + JSON Lines
│   │   ├── config.py           # Pydantic v2 settings
│   │   ├── output.py           # JSON / HTML / CSV / PCAP output
│   │   └── privilege.py        # Root / CAP_NET_RAW detection
│   │
│   ├── modules/
│   │   ├── dns_enum.py
│   │   ├── host_discovery.py
│   │   ├── os_fingerprint.py
│   │   ├── port_scan.py
│   │   ├── vuln_scan.py
│   │   ├── wireless.py
│   │   └── pcap_capture.py
│   │
│   ├── data/
│   │   ├── cve_db.json             # 55 CVE entries
│   │   ├── service_probes.json     # 35+ service probes
│   │   ├── default_creds.json      # 13 credential sets
│   │   └── wordlists/
│   │       ├── dns_resolvers.txt
│   │       └── subdomains_top5000.txt
│   │
│   ├── reports/
│   │   └── template.html           # Jinja2 dark-theme report template
│   │
│   └── tests/                      # 62 tests, all passing
│       ├── test_config.py
│       ├── test_dns_enum.py
│       ├── test_output.py
│       ├── test_port_scan.py
│       └── test_vuln_scan.py
│
└── utils/                          # Standalone utility scripts
    ├── recon_utils.py
    └── wireless.py
```

---

## Examples

### Complete Network Assessment

```bash
# Discover live hosts
python recon.py discover -t 192.168.1.0/24 --all

# Port scan a specific host
python recon.py portscan -t 192.168.1.100 -s connect -p top1000

# Vulnerability assessment
python recon.py vulnscan -t 192.168.1.100 --all

# Full pipeline + HTML report
python recon.py full -t 192.168.1.100 --out ./report
```

### DNS Reconnaissance

```bash
python recon.py dns -d target.com --full --threads 20
python recon.py dns -d target.com --brute -w /path/to/wordlist.txt
python recon.py dns -d target.com --reverse 10.0.0.0/24
```

### Privilege-Aware Port Scanning

```bash
python recon.py privcheck

# Root: stealth SYN scan
sudo python recon.py portscan -t 192.168.1.100 -s syn -p top1000

# Non-root: connect scan
python recon.py portscan -t 192.168.1.100 -s connect -p top1000
```

---

## Testing

```bash
# Run all 62 tests
pytest recon/tests/ -v

# Single test file
pytest recon/tests/test_port_scan.py -v

# With coverage
pytest recon/tests/ --cov=recon --cov-report=html
```

---

## Legal Notice

**⚠ AUTHORIZED USE ONLY**

This toolkit is for authorized security testing and educational purposes only. Use against systems without explicit written permission violates:

- **USA** — Computer Fraud and Abuse Act (CFAA)
- **UK** — Computer Misuse Act 1990
- **India** — IT Act 2000
- **EU** — ePrivacy Directive & NIS Directive
- Other jurisdictions: equivalent cybercrime laws

By using this toolkit you confirm you have written authorization from the target system owner.

---

*Recon Toolkit v2.0 — built by Swastik*
