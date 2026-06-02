# Reconnaissance Toolkit v2.0

**Production-Grade Network Reconnaissance Suite**
**62/62 Tests Passing • 8 CLI Subcommands • Multi-Format Output**

---

## Quick Overview

| Component | Status | Details |
|-----------|--------|---------|
| **CLI** | ✅ Ready | Typer-based with 8 subcommands |
| **Tests** | ✅ 62/62 | Config, DNS, ports, vulns, output |
| **Modules** | ✅ 7 | DNS, host discovery, OS, ports, vulns, wireless, PCAP |
| **CVE Database** | ✅ 55 | Apache, SSH, Log4j, Exchange, F5, Citrix, VMware... |
| **Service Probes** | ✅ 35+ | HTTP, SSH, Redis, ES, Docker, K8s... |
| **Default Creds** | ✅ 13 | FTP, SSH, HTTP, Redis, MySQL, MongoDB... |

---

## Table of Contents

1. [Installation](#installation)
2. [Quick Start](#quick-start)
3. [CLI Reference](#cli-reference)
4. [Modules Overview](#modules-overview)
5. [Output Formats](#output-formats)
6. [Project Structure](#project-structure)
7. [Examples](#examples)
8. [Testing](#testing)
9. [Legal Notice](#legal-notice)

---

## Installation

### Prerequisites
- **Python 3.12+**
- **pip** or similar package manager
- **Linux/macOS** recommended (Windows: limited features)

### Install Dependencies

```bash
# Core requirements
pip install -r requirements.txt

# Optional: raw socket scanning (Scapy)
pip install scapy

# Optional: for raw packet manipulation
pip install cryptography>=41.0.0
```

### Verify Installation

```bash
# Check privilege status
python recon.py privcheck

# Show all available commands
python recon.py --help
```

---

## Quick Start

### Basic Commands

```bash
# DNS enumeration
python recon.py dns -d target.com --full

# Host discovery (no root needed)
python recon.py discover -t 192.168.1.0/24 --tcp --icmp

# Port scan (connect mode, no root)
python recon.py portscan -t 192.168.1.100 -s connect -p top1000

# OS fingerprinting
python recon.py os -t 192.168.1.100

# Vulnerability assessment
python recon.py vulnscan -t 192.168.1.100 --all

# Full pipeline → HTML report (auto-opens browser)
python recon.py full -t 192.168.1.100 --out ./report

# Check privilege status
python recon.py privcheck

# Run tests
pytest recon/tests/ -v
```

---

## CLI Reference

### Core Subcommands

| Command | Purpose | Requires Root? |
|---------|---------|---|
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
  --full              Run all DNS methods (AXFR + records + brute-force)
  --axfr              Zone transfer detection only
  --records           Query A, AAAA, MX, NS, TXT, SRV, SOA
  --brute             Subdomain brute-force with wordlist
  --wildcard          Detect wildcard DNS entries
  --dnssec            Validate DNSSEC signatures
  --doh               Use DNS over HTTPS (Cloudflare, Quad9)
  --wordlist FILE     Custom subdomain wordlist
  --threads N         Thread count (default: 10)
  --output {json,csv} Output format
```

**Example:**
```bash
python recon.py dns -d target.com --full --threads 20 --output json
```

---

#### **discover** — Host Discovery

```bash
python recon.py discover -t 192.168.1.0/24 [OPTIONS]

Options:
  --arp               ARP sweep (Layer 2)
  --icmp              ICMP echo sweep (Layer 3)
  --tcp               TCP SYN/ACK sweep on ports 22,80,443,445
  --udp               UDP sweep (DNS, NTP, SNMP)
  --all               All methods combined (default)
  --threads N         Thread count (default: 50)
  --timeout SECONDS   Per-host timeout (default: 1.0)
  --output {json,csv} Output format
```

**Example:**
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
  --tcp               TCP stack analysis (requires root)
  --banners           Banner grabbing on common ports
  --icmp              ICMP quirk probes
  --ports PORTS       Custom port list (default: 21,22,80,443,3306,6379)
  --timeout SECONDS   Connection timeout (default: 3)
  --output {json,csv} Output format
```

**Example:**
```bash
python recon.py os -t 192.168.1.100 --full --output json
```

---

#### **portscan** — Port Scanning

```bash
python recon.py portscan -t 192.168.1.100 [OPTIONS]

Options:
  -s, --scan-type {connect,syn,fin,xmas,null,ack,udp}
                      Scan technique (default: connect)
  -p, --ports {top20,top100,top1000,all,PORTS}
                      Port selection (default: top1000)
  --threads N         Thread count (default: 200)
  --timeout SECONDS   Per-port timeout (default: 1.0)
  --output {json,csv} Output format

Scan Types:
  connect   — Full TCP handshake (no root required)
  syn       — Half-open stealth scan (requires root/CAP_NET_RAW)
  fin       — FIN flag sweep (requires root)
  xmas      — FIN+PSH+URG flags (requires root)
  null      — No flags set (requires root)
  ack       — ACK scan for firewall rule detection (requires root)
  udp       — UDP probe sweep (requires root)
```

**Example:**
```bash
python recon.py portscan -t 192.168.1.100 -s connect -p top1000
```

---

#### **vulnscan** — Vulnerability Assessment

```bash
python recon.py vulnscan -t 192.168.1.100 [OPTIONS]

Options:
  --all               Run all checks (CVE + SSL + creds + misconfigs)
  --cve               Match service banners against CVE database
  --ssl               Check SSL/TLS certificate and configuration
  --creds             Test default credentials
  --misconfig         Detect common misconfigurations
  --ports PORTS       Custom port list (auto-scans if not specified)
  --output {json,csv} Output format
```

**Example:**
```bash
python recon.py vulnscan -t 192.168.1.100 --all --output json
```

---

#### **wireless** — Wireless Reconnaissance

```bash
python recon.py wireless [OPTIONS]

Options:
  --list              Show available wireless adapters
  --interface IF      Target interface (auto-detected if not specified)
  --monitor           Enable monitor mode
  --managed           Disable monitor mode (restore to managed)
  --channels CHANS    Channel list (default: 1-13 for 2.4GHz)
  --dwell MS          Milliseconds per channel (default: 500)
```

**Example:**
```bash
# Requires root on Linux
sudo python recon.py wireless --list
sudo python recon.py wireless --monitor --channels 1,6,11
```

---

#### **full** — Full Pipeline with Report

```bash
python recon.py full -t 192.168.1.100 [OPTIONS]

Options:
  --out DIRECTORY     Output directory for reports (default: ./reports)
  --dns-full          Enable full DNS enumeration
  --port-scan {syn,connect}
                      Port scan method (default: connect)
  --vuln-all          Run all vulnerability checks
  --html              Generate HTML report (default: enabled)
  --open              Auto-open HTML report in browser
```

**Example:**
```bash
python recon.py full -t 192.168.1.100 --out ./results --html --open
```

---

#### **privcheck** — Privilege Status

```bash
python recon.py privcheck

Output:
  Current user: user / root
  Scapy available: Yes / No
  CAP_NET_RAW: Yes / No (on Linux)
  Effective UID: 0 / 1000 (etc.)
```

---

## Modules Overview

All modules in `recon/modules/`:

| Module | Purpose | Lines | Features |
|--------|---------|-------|----------|
| `dns_enum.py` | DNS Enumeration | ~300 | AXFR, wildcards, brute-force, DNSSEC, DoH |
| `host_discovery.py` | Host Discovery | ~280 | ARP, ICMP, TCP, UDP with OUI lookup |
| `os_fingerprint.py` | OS Fingerprinting | ~270 | 15 signatures, TTL, banners, ICMP quirks |
| `port_scan.py` | Port Scanning | ~380 | SYN/Connect/FIN/XMAS/NULL/ACK/UDP |
| `vuln_scan.py` | Vulnerability Scan | ~490 | CVE matching, SSL audit, default creds |
| `wireless.py` | Wireless Recon | ~340 | Monitor mode, channel hop, 802.11 parsing |
| `pcap_capture.py` | PCAP Capture | ~190 | AsyncSniffer, ring-buffer, thread-safe |

---

## Output Formats

### JSON Output

```bash
python recon.py portscan -t 192.168.1.100 --output json
```

**Output structure:**
```json
{
  "command": "portscan",
  "target": "192.168.1.100",
  "timestamp": "2026-06-02T14:30:00Z",
  "results": [
    {
      "port": 22,
      "status": "open",
      "service": "ssh",
      "version": "OpenSSH 7.4"
    }
  ]
}
```

### CSV Output

```bash
python recon.py vulnscan -t 192.168.1.100 --output csv
```

**Output structure:**
```
target,port,service,vulnerability,severity,cvss
192.168.1.100,22,ssh,CVE-2023-1234,High,7.5
192.168.1.100,80,http,Missing Security Headers,Medium,5.3
```

### HTML Report

```bash
python recon.py full -t 192.168.1.100 --out ./report --open
```

**Features:**
- Dark theme with responsive design
- Sortable and searchable tables
- Severity-color-coded badges (Critical/High/Medium/Low)
- Timeline-based vulnerability display
- Auto-opens in default browser
- Self-contained single HTML file

### PCAP Output

Packet capture files are automatically generated during scans:

```
DNS_Enumeration_20260602_143000.pcap
Host_Discovery_20260602_143100.pcap
Port_Scan_20260602_143200.pcap
```

Read with Wireshark, tcpdump, or `scapy`:

```python
from scapy.all import rdpcap
packets = rdpcap('Port_Scan_20260602_143200.pcap')
for pkt in packets:
    print(pkt.summary())
```

---

## Project Structure

```
recon-toolkit/
├── recon.py                 # Main CLI entry point (Typer)
├── requirements.txt         # Python dependencies
├── README.md               # This file
│
├── recon/
│   ├── __init__.py
│   ├── core/               # Core infrastructure
│   │   ├── config.py       # Pydantic v2 settings + TOML
│   │   ├── logger.py       # Rich console + JSON Lines logging
│   │   ├── output.py       # Multi-format output (JSON/CSV/HTML/PCAP)
│   │   └── privilege.py    # Privilege detection (root/CAP_NET_RAW)
│   │
│   ├── modules/            # Reconnaissance engines
│   │   ├── dns_enum.py     # DNS enumeration (~300 lines)
│   │   ├── host_discovery.py # Host discovery (~280 lines)
│   │   ├── os_fingerprint.py # OS fingerprinting (~270 lines)
│   │   ├── port_scan.py    # Port scanning (~380 lines)
│   │   ├── vuln_scan.py    # Vulnerability assessment (~490 lines)
│   │   ├── wireless.py     # Wireless reconnaissance (~340 lines)
│   │   └── pcap_capture.py # PCAP packet capture (~190 lines)
│   │
│   ├── data/               # Reconnaissance data
│   │   ├── cve_db.json     # 55 CVEs (Apache, SSH, Log4j, etc.)
│   │   ├── service_probes.json # 35+ service identification probes
│   │   ├── default_creds.json  # 13 default credential sets
│   │   └── wordlists/
│   │       ├── dns_resolvers.txt
│   │       └── subdomains_top5000.txt
│   │
│   ├── reports/            # Report generation
│   │   └── template.html   # Jinja2 dark-theme HTML template
│   │
│   └── tests/              # Comprehensive test suite
│       ├── test_config.py
│       ├── test_dns_enum.py
│       ├── test_output.py
│       ├── test_port_scan.py
│       └── test_vuln_scan.py (62 tests total, all passing)
│
└── docs/                   # Documentation
    └── THEORETICAL_ANALYSIS.md
```

---

## Examples

### Example 1: Complete Network Assessment

```bash
# Stage 1: Host discovery (no root needed)
python recon.py discover -t 192.168.1.0/24 --tcp --icmp --output json > hosts.json

# Stage 2: OS fingerprint discovered hosts
for host in $(cat hosts.json | jq -r '.results[].ip'); do
  python recon.py os -t $host --output json >> os_results.json
done

# Stage 3: Full vulnerability assessment
python recon.py vulnscan -t 192.168.1.100 --all --output json > vuln_results.json

# Stage 4: Generate HTML report
python recon.py full -t 192.168.1.100 --out ./final_report --open
```

### Example 2: DNS Reconnaissance Only

```bash
# Full DNS enumeration
python recon.py dns -d target.com --full --threads 20 --output json

# Extract findings
cat dns_results.json | jq '.results[] | select(.type=="A") | .value'
```

### Example 3: Port Scanning with Privilege Detection

```bash
# Check what we can do
python recon.py privcheck

# If root: use SYN for stealth
sudo python recon.py portscan -t 192.168.1.100 -s syn -p top1000 --output json

# If non-root: fall back to Connect mode
python recon.py portscan -t 192.168.1.100 -s connect -p top1000 --output json
```

### Example 4: Vulnerability Assessment Pipeline

```bash
# Quick vulnerability check
python recon.py vulnscan -t 192.168.1.100 --cve --ssl --output csv

# Deep dive with default credentials
python recon.py vulnscan -t 192.168.1.100 --all --ports 22,23,3306,6379 --output json
```

---

## Testing

All 62 tests passing ✅

```bash
# Run all tests
pytest recon/tests/ -v

# Run specific test file
pytest recon/tests/test_dns_enum.py -v

# Run with coverage
pytest recon/tests/ --cov=recon --cov-report=html
```

---

## Legal Notice

**⚠️ AUTHORIZED USE ONLY**

This toolkit is designed for authorized security testing and educational purposes only. 

**Unauthorized access to computer systems is illegal.** Using this toolkit against systems without explicit written permission violates:
- USA: Computer Fraud and Abuse Act (CFAA)
- UK: Computer Misuse Act 1990
- EU: ePrivacy Directive & NIS Directive
- Other jurisdictions: equivalent cybercrime laws

**By using this toolkit, you agree to:**
1. Obtain written authorization before testing any system
2. Conduct testing only within the scope defined in your authorization
3. Comply with all applicable laws and regulations
4. Accept full responsibility for any misuse

---

## Support & Contributing

- **GitHub:** [amibhai/recon-toolkit](https://github.com/amibhai/recon-toolkit)
- **Issues:** Report bugs and request features on GitHub Issues
- **Security:** Do not disclose vulnerabilities publicly; contact maintainer privately

---

## Version History

| Version | Date | Notes |
|---------|------|-------|
| **v2.0** | 2026-06-02 | Production release with Typer CLI, 62 tests, 7 modules |
| v1.0 | 2026-05-01 | Initial release with legacy menu system |

---

**Recon Toolkit v2.0 — Ready for Production Security Assessments** 🚀
