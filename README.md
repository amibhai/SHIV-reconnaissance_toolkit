# Reconnaissance Toolkit

**Complete, Sophisticated Network Reconnaissance Suite**
**Standalone Repository — No External Toolkit Dependencies**

---

## Table of Contents

1. [Tools Overview](#tools-overview)
2. [Interactive Menu](#interactive-menu)
   - [Running the Menu](#running-the-menu)
   - [Main Menu](#main-menu)
   - [1 — DNS Enumeration](#1--dns-enumeration-submenu)
   - [2 — Host Discovery](#2--host-discovery-submenu)
   - [3 — OS Scan](#3--os-scan-submenu)
   - [4 — Ping Sweep](#4--ping-sweep-submenu)
   - [5 — Port Scan](#5--port-scan-submenu)
   - [6 — Vulnerability Scan](#6--vulnerability-scan-submenu)
   - [7 — Wireless Adapter](#7--wireless-adapter-submenu)
   - [P — PCAP Settings](#p--pcap-settings-submenu)
3. [Quick Start (CLI)](#quick-start-cli)
4. [Detailed Tool Reference](#detailed-tool-reference)
5. [Output Files](#output-files)
6. [Project Structure](#project-structure)
7. [Installation](#installation)
8. [Evasion Techniques](#evasion-techniques)

---

## Tools Overview

| Tool | File | Description |
|------|------|-------------|
| DNS Enumeration | `tools/dns_enum.py` | Zone transfers, subdomain brute-force, record enumeration |
| Host Discovery | `tools/host_discovery.py` | ARP sweep, ICMP, TCP/UDP multi-method |
| OS Scan | `tools/os_scan.py` | TTL, TCP stack, banner fingerprinting |
| Ping Sweep | `tools/ping_sweep.py` | Fast threaded ICMP/TCP/UDP sweep |
| Port Scan | `tools/port_scan.py` | SYN/Connect/FIN/XMAS/ACK/UDP scans |
| Vulnerability Scan | `tools/vuln_scan.py` | CVE detection, SSL audit, default creds |

---

## Interactive Menu

The toolkit ships with a full-featured interactive terminal menu (`tools/recon_menu.py`) that lets you configure and launch any scan without remembering CLI flags.

### Running the Menu

```bash
# Recommended — enables all features (raw sockets, monitor mode, PCAP)
sudo python3 tools/recon_menu.py

# Non-root — reduced feature set (no SYN scans, no ARP, no monitor mode)
python3 tools/recon_menu.py
```

On startup the menu clears the screen, draws the ASCII **RECON** banner, and shows a status bar indicating:
- `root ✓` / `non-root ⚠` — privilege level
- `Scapy ✓` / `Scapy ✗` — whether Scapy is installed
- PCAP capture state (ON / OFF)

---

### Main Menu

```
╔══════════════════════════════════════════════════════════════════════╗
║          RECONNAISSANCE TOOLKIT  —  INTERACTIVE MENU                ║
║                                                                      ║
║  1. DNS Enumeration      — zone transfer, records, subdomain brute   ║
║  2. Host Discovery       — ARP, ICMP, TCP, UDP multi-method          ║
║  3. OS Scan              — TTL, TCP stack, banners, ICMP quirks      ║
║  4. Ping Sweep           — threaded ICMP/TCP with evasion options    ║
║  5. Port Scan            — SYN/Connect/FIN/XMAS/ACK/UDP + services  ║
║  6. Vulnerability Scan   — CVE DB, SSL audit, default creds          ║
║  7. Wireless Adapter     — auto-detect, monitor mode, hop channels   ║
║  P. PCAP Settings        — toggle capture, set output directory      ║
║  0. Exit                                                             ║
╚══════════════════════════════════════════════════════════════════════╝
```

| Key | Action |
|-----|--------|
| `1` | Open DNS Enumeration submenu |
| `2` | Open Host Discovery submenu |
| `3` | Open OS Scan submenu |
| `4` | Open Ping Sweep submenu |
| `5` | Open Port Scan submenu |
| `6` | Open Vulnerability Scan submenu |
| `7` | Open Wireless Adapter submenu |
| `P` | Open PCAP Settings submenu |
| `0` | Exit the toolkit |

After every scan completes you are returned to the submenu. Press `0` in any submenu to return to the Main Menu.

---

### 1 — DNS Enumeration Submenu

Launches `DNSEnumerator` from `dns_enum.py`.

| Option | Description |
|--------|-------------|
| `1` Full enumeration | Runs all methods: zone transfer → record enum → subdomain brute-force → reverse sweep |
| `2` Zone transfer only | Sends AXFR requests to every authoritative nameserver for the domain |
| `3` DNS records only | Queries A, AAAA, MX, NS, TXT, CNAME, SOA, SRV, CAA records |
| `4` Subdomain brute-force | Wildcard-check then threaded brute-force using built-in or custom wordlist |
| `5` Reverse DNS sweep | PTR lookups for every IP in a given CIDR range |
| `0` Back | Return to main menu |

**Prompted parameters:**

| Parameter | Default | Notes |
|-----------|---------|-------|
| Target domain | `example.com` | e.g. `target.org` |
| Threads | `10` | 1–200; more = faster brute-force |
| Timeout (s) | `3` | Per-query timeout |
| Subdomain wordlist | `wordlists/subdomains.txt` | Only shown for options 1 & 4 |
| CIDR range | `192.168.1.0/24` | Only shown for option 5 |

**PCAP:** Capture file will be named `DNS_Enumeration_YYYYMMDD_HHMMSS.pcap`.

---

### 2 — Host Discovery Submenu

Launches `HostDiscovery` from `host_discovery.py`.

| Option | Description |
|--------|-------------|
| `1` Full discovery | Combines ARP + ICMP + TCP fallback; deduplicates results |
| `2` ARP sweep only | Layer 2 — most reliable for local subnets, retrieves MAC + vendor |
| `3` ICMP sweep only | Standard ping sweep |
| `4` TCP sweep only | Probes ports 22, 80, 443, 445 — **no root required** |
| `5` UDP probe sweep | DNS (53), NTP (123), SNMP (161) probes to find UDP-only hosts |
| `0` Back | Return to main menu |

**Prompted parameters:**

| Parameter | Default | Notes |
|-----------|---------|-------|
| Target | `192.168.1.0/24` | IP, CIDR block, or range (e.g. `10.0.0.1-254`) |
| Threads | `50` | 1–500 |
| Timeout (s) | `1.0` | Float, per-host |

**PCAP:** Capture file will be named `Host_Discovery_YYYYMMDD_HHMMSS.pcap`.

---

### 3 — OS Scan Submenu

Launches `OSScanner` from `os_scan.py`.

| Option | Description |
|--------|-------------|
| `1` Full OS scan | All methods combined; highest confidence score (needs root) |
| `2` TTL fingerprint | Sends ICMP echo and reads TTL (64=Linux, 128=Windows, 255=Cisco) — fast, no root |
| `3` TCP stack analysis | Probes a port for TCP window size, options, DF bit (root needed) |
| `4` Banner grabbing | Connects to service ports and extracts version strings |
| `5` ICMP quirk probes | Sends ICMP Type 13 (timestamp) and Type 17 (address mask) requests |
| `0` Back | Return to main menu |

**Prompted parameters:**

| Parameter | Default | Notes |
|-----------|---------|-------|
| Target IP / hostname | `192.168.1.100` | Single host only |
| Timeout (s) | `3` | 1–30 |
| Ports for banner scan | `21,22,80,443,3306,6379` | Shown for options 1 & 4 |
| Port for TCP fingerprint | `80` | Shown for option 3 only |

**PCAP:** Capture file will be named `OS_Scan_YYYYMMDD_HHMMSS.pcap`.

---

### 4 — Ping Sweep Submenu

Launches `PingSweep` from `ping_sweep.py`.

| Option | Description |
|--------|-------------|
| `1` Standard sweep | ICMP → system ping fallback → TCP fallback; 100 threads, 1 s timeout |
| `2` Randomized sweep | Same as standard but shuffles host order to evade sequential IDS signatures |
| `3` Fast sweep | 300 threads, 0.3 s timeout — best for large /16 or /8 ranges |
| `4` Custom sweep | Manually set threads, timeout, and randomize flag |
| `0` Back | Return to main menu |

**Prompted parameters (option 4 only):**

| Parameter | Default | Notes |
|-----------|---------|-------|
| Target | `192.168.1.0/24` | IP, CIDR, or range |
| Threads | `100` | 1–1000 |
| Timeout (s) | `1.0` | Float |
| Randomize? | `n` | `y` shuffles target list |

**PCAP:** Capture file will be named `Ping_Sweep_YYYYMMDD_HHMMSS.pcap`.

---

### 5 — Port Scan Submenu

Launches `PortScanner` from `port_scan.py`.

#### TCP Scans

| Option | Scan Type | Root | Stealth | Notes |
|--------|-----------|------|---------|-------|
| `1` | SYN (half-open) | Yes | High | Never completes TCP handshake; most IDS-evasive |
| `2` | Connect (full TCP) | No | Low | Most reliable; logs appear on target |
| `3` | FIN | Yes | High | Sends only FIN; closed ports reply RST |
| `4` | XMAS | Yes | High | Sets FIN+PSH+URG flags |
| `5` | ACK | Yes | Medium | Detects firewall rules (filtered vs. unfiltered) |

#### UDP & Combined

| Option | Description |
|--------|-------------|
| `6` UDP scan | Sends crafted UDP probes to DNS/SNMP/NTP/NetBIOS ports |
| `7` Full scan | SYN TCP scan + UDP scan combined (root needed) |

#### Port Presets

| Preset | Ports |
|--------|-------|
| `top20` | 20 most common service ports |
| `top100` | 100 common service ports |
| `all` | All 65535 ports (slow — use with small timeout) |
| `1-1024` | Well-known port range |
| `80,443,8080` | Custom comma-separated list |

**Prompted parameters:**

| Parameter | Default | Notes |
|-----------|---------|-------|
| Target IP / hostname | `192.168.1.100` | Single host |
| Port range / preset | `top100` | See presets above |
| Threads | `200` | 1–1000 |
| Timeout (s) | `1.0` | Float |

**PCAP:** Capture file will be named `Port_Scan_YYYYMMDD_HHMMSS.pcap`.

---

### 6 — Vulnerability Scan Submenu

Launches `VulnerabilityScanner` from `vuln_scan.py`.

| Option | Description |
|--------|-------------|
| `1` Full vulnerability scan | Auto port-scans target, then runs all checks |
| `2` Specific ports only | You supply a port list; runs all checks on those ports |
| `3` SSL/TLS audit only | Checks protocol versions, ciphers, certificate validity |
| `4` CVE banner check | Grabs service banners and matches against the built-in CVE database |
| `5` Default credential test | Tests default/known-weak logins for FTP or Redis |
| `6` Misconfiguration check | Detects open Telnet, anonymous FTP, unauthenticated Redis/MongoDB |
| `0` Back | Return to main menu |

**Prompted parameters:**

| Parameter | Notes |
|-----------|-------|
| Target IP / hostname | Single host |
| Timeout (s) | 1–60 s |
| Ports (option 2, 4, 6) | Comma-separated, e.g. `22,80,443,21,6379` |
| SSL/TLS port (option 3) | Default `443` |
| Service (option 5) | `ftp` or `redis` |

**CVE Database covers:** OpenSSH · Apache · nginx · OpenSSL · MySQL · vsftpd · Log4j · Struts · ProFTPD · Samba

**PCAP:** Capture file will be named `Vuln_Scan_YYYYMMDD_HHMMSS.pcap`.

---

### 7 — Wireless Adapter Submenu

Launches `WirelessManager` from `wireless.py`.

> **Requires root on Linux.** Not available on Windows.

| Option | Description |
|--------|-------------|
| `1` Auto-setup | Detects the first available wireless adapter and enables monitor mode; optionally starts channel hopping |
| `2` List wireless interfaces | Shows all detected interfaces with their current mode and MAC address |
| `3` Enable monitor mode | Enables monitor mode on a user-specified interface |
| `4` Disable monitor mode | Restores the interface to managed mode |
| `5` Start channel hopping | Continuously cycles through specified 2.4 GHz channels at a configurable interval |
| `0` Back | Return to main menu |

**Prompted parameters (option 5):**

| Parameter | Default | Notes |
|-----------|---------|-------|
| Monitor interface | `wlan0mon` | Auto-detected if available |
| Channels | `1,2,3,…,13` | Comma-separated channel list |
| Seconds per channel | `0.5` | Float |

Press **Ctrl+C** to stop channel hopping. Monitor mode is automatically restored to managed mode on exit.

---

### P — PCAP Settings Submenu

Controls the **inline passive packet capture** engine that sniffs all traffic in a background thread while any scan is running.

```
PCAP Settings
─────────────────────────────────────────────────
  1.  Toggle PCAP      (currently ON / OFF)
  2.  Set output directory   (current: ./pcaps)
  0.  Back to main menu
```

| Option | Description |
|--------|-------------|
| `1` Toggle PCAP | Switches global PCAP capture ON or OFF for all subsequent scans |
| `2` Set output directory | Changes where `.pcap` files are saved (directory is created automatically) |
| `0` Back | Return to main menu |

#### How PCAP Capture Works

1. **Global ON** — Every scan automatically starts a background sniffer thread before the scan begins and stops it afterwards, flushing all captured packets to a `.pcap` file.
2. **Global OFF** — Before each scan you are asked _"Save this scan to a PCAP file? (y/n)"_. Answering `y` enables capture for that single scan only.
3. **File naming format:** `<ScanName>_YYYYMMDD_HHMMSS.pcap`  
   Example: `DNS_Enumeration_20240427_143022.pcap`
4. **Requires Scapy** — If Scapy is not installed, PCAP capture is silently skipped. Install with `pip3 install scapy`.

> **Note:** PCAP status is always shown on every menu screen so you always know whether capture is active.

---

## Quick Start (CLI)

```bash
# Install dependencies
pip3 install scapy dnspython

# DNS Enumeration
python3 tools/dns_enum.py -d target.com

# DNS Zone Transfer only
python3 tools/dns_enum.py -d target.com --zone-transfer

# Subdomain brute-force with custom wordlist
python3 tools/dns_enum.py -d target.com --subdomains-only -w wordlists/subdomains.txt

# Host Discovery - full range
sudo python3 tools/host_discovery.py -t 192.168.1.0/24

# Host Discovery - ARP only
sudo python3 tools/host_discovery.py -t 192.168.1.0/24 --arp

# OS Fingerprinting
sudo python3 tools/os_scan.py -t 192.168.1.100

# OS Scan - banner grabbing only
python3 tools/os_scan.py -t 192.168.1.100 --banner-only

# Ping Sweep
sudo python3 tools/ping_sweep.py -t 192.168.1.0/24

# Ping Sweep - randomized (evasion)
sudo python3 tools/ping_sweep.py -t 192.168.1.0/24 --randomize

# Port Scan - SYN scan (stealthiest, requires root)
sudo python3 tools/port_scan.py -t 192.168.1.100 -s syn -p top100

# Port Scan - Connect scan (no root needed)
python3 tools/port_scan.py -t 192.168.1.100 -s connect -p top100

# Port Scan - Full range
sudo python3 tools/port_scan.py -t 192.168.1.100 -s syn -p all

# Port Scan - Custom ports with UDP
sudo python3 tools/port_scan.py -t 192.168.1.100 -p 80,443,8080,8443 --udp

# Vulnerability Scan
python3 tools/vuln_scan.py -t 192.168.1.100

# Vulnerability Scan - SSL audit only
python3 tools/vuln_scan.py -t 192.168.1.100 --ssl-only --ssl-port 443

# Vulnerability Scan - specific ports
python3 tools/vuln_scan.py -t 192.168.1.100 -p 22,80,443,3306
```

---

## Detailed Tool Reference

### DNS Enumeration (`dns_enum.py`)

**Features:**
- Zone transfer attempts (AXFR) against all nameservers
- All DNS record types (A, AAAA, MX, NS, TXT, CNAME, SOA, SRV, CAA)
- Multi-threaded subdomain brute-force (built-in 100+ subdomain list)
- Custom wordlist support
- Wildcard DNS detection (prevents false positives)
- Reverse DNS sweeps over CIDR ranges
- DNS cache snooping
- JSON + TXT output

```bash
# Full enumeration
python3 tools/dns_enum.py -d example.com

# Zone transfer attempt
python3 tools/dns_enum.py -d example.com --zone-transfer

# Reverse DNS sweep
python3 tools/dns_enum.py -d example.com --reverse-cidr 192.168.1.0/24

# With custom subdomain list
python3 tools/dns_enum.py -d example.com -w wordlists/subdomains.txt -t 20
```

---

### Host Discovery (`host_discovery.py`)

**Features:**
- ARP sweep (Layer 2 — most reliable for local networks)
- MAC address + vendor identification
- Multi-threaded ICMP sweep
- TCP-based discovery (probes ports 22, 80, 443, 445)
- UDP discovery (DNS, NTP, SNMP probes)
- TTL-based OS hints
- Reverse DNS for each live host
- Deduplication across methods

```bash
# Full discovery (all methods)
sudo python3 tools/host_discovery.py -t 192.168.1.0/24

# ARP only
sudo python3 tools/host_discovery.py -t 192.168.1.0/24 --arp

# TCP only (no root needed)
python3 tools/host_discovery.py -t 192.168.1.0/24 --tcp

# IP range
sudo python3 tools/host_discovery.py -t 192.168.1.1-254
```

---

### OS Scan (`os_scan.py`)

**Features:**
- TTL-based OS guessing (64=Linux, 128=Windows, 255=Cisco)
- TCP SYN-ACK analysis (window size, TCP options, DF bit)
- OS signature database (12 OS profiles)
- Banner grabbing from 14 service ports
- ICMP quirk probes (types 13, 17)
- Version extraction from banners
- Confidence scoring across methods

```bash
# Full OS fingerprint
sudo python3 tools/os_scan.py -t 192.168.1.100

# TTL only (fast)
python3 tools/os_scan.py -t 192.168.1.100 --ttl-only

# Banner only (no root)
python3 tools/os_scan.py -t 192.168.1.100 --banner-only

# Custom ports for banner
python3 tools/os_scan.py -t 192.168.1.100 --banner-only -p 22,80,8080,3306
```

---

### Ping Sweep (`ping_sweep.py`)

**Features:**
- Scapy ICMP (requires root, most accurate)
- System ping fallback (no root needed)
- TCP ping fallback (ports 80, 443, 22)
- Configurable threads (default 100)
- Randomized sweep order for evasion
- TTL-based OS hints per host
- Reverse DNS for live hosts
- Sorted live host summary

```bash
# Standard sweep
sudo python3 tools/ping_sweep.py -t 192.168.1.0/24

# Fast sweep (200 threads)
sudo python3 tools/ping_sweep.py -t 192.168.1.0/24 --threads 200

# Randomized order (evades sequential IDS detection)
sudo python3 tools/ping_sweep.py -t 192.168.1.0/24 --randomize

# Tight timeout
sudo python3 tools/ping_sweep.py -t 10.0.0.0/24 --timeout 0.5 --threads 500

# IP range
sudo python3 tools/ping_sweep.py -t 192.168.1.1-254
```

---

### Port Scan (`port_scan.py`)

**Scan Types:**

| Type | Flags | Root | Stealth | Reliability |
|------|-------|------|---------|-------------|
| `syn` | SYN | Yes | High | High |
| `connect` | Full | No | Low | Very High |
| `fin` | FIN | Yes | High | Medium |
| `xmas` | FIN+PSH+URG | Yes | High | Medium |
| `ack` | ACK | Yes | Medium | Firewall detection |
| `udp` | UDP | Yes | N/A | Medium |

**Port Presets:**
- `top20` — 20 most important ports
- `top100` — 100 common ports
- `all` — All 65535 ports
- `1-1024` — Custom range
- `80,443,8080` — Specific ports

```bash
# SYN scan top 100 (default)
sudo python3 tools/port_scan.py -t 192.168.1.100 -s syn -p top100

# Connect scan (no root)
python3 tools/port_scan.py -t 192.168.1.100 -s connect

# Full range SYN scan
sudo python3 tools/port_scan.py -t 192.168.1.100 -s syn -p all

# FIN scan (stealth)
sudo python3 tools/port_scan.py -t 192.168.1.100 -s fin -p top100

# With UDP
sudo python3 tools/port_scan.py -t 192.168.1.100 --udp

# Specific ports
python3 tools/port_scan.py -t 192.168.1.100 -p 22,80,443,3306,5432,27017
```

---

### Vulnerability Scan (`vuln_scan.py`)

**Features:**

1. **CVE Database** (20+ CVEs):
   - OpenSSH 7.4 → CVE-2018-15473 (user enum)
   - Apache 2.4.49 → CVE-2021-41773 (RCE)
   - vsftpd 2.3.4 → CVE-2011-2523 (backdoor)
   - Log4j 2.x → CVE-2021-44228 (Log4Shell)
   - Struts 2 → CVE-2017-5638 (Equifax breach)
   - ProFTPD 1.3.5 → CVE-2015-3306 (RCE)
   - Samba 4.6.3 → CVE-2017-7494 (SambaCry)

2. **SSL/TLS Audit**:
   - Protocol version checks (SSLv2/3, TLS 1.0/1.1/1.2/1.3)
   - Certificate validation (self-signed, expiry)
   - Cipher suite weakness

3. **Default Credentials**:
   - FTP (anonymous, admin:admin, etc.)
   - Redis (no auth)
   - SNMP (public/private community strings)

4. **Misconfigurations**:
   - FTP anonymous access
   - Telnet enabled
   - Redis without authentication
   - MongoDB exposed
   - HTTP Basic Auth over plain HTTP

```bash
# Full vulnerability scan
python3 tools/vuln_scan.py -t 192.168.1.100

# SSL audit only
python3 tools/vuln_scan.py -t 192.168.1.100 --ssl-only

# Specific ports
python3 tools/vuln_scan.py -t 192.168.1.100 -p 22,80,443,21,6379
```

---

## Wireless Features

```bash
# Auto-detect wireless adapter and enable monitor mode
sudo python3 tools/wireless.py
```

**Capabilities:**
- Automatic adapter detection (sysfs, iw, iwconfig)
- Monitor mode via airmon-ng or manual iw method
- Kills interfering processes automatically
- Channel hopping support
- Managed mode restoration on exit
- Multiple adapter support

---

## Output Files

All results saved to `output/` directory:
- `output/dns_enumeration_YYYYMMDD_HHMMSS.json`
- `output/host_discovery_YYYYMMDD_HHMMSS.txt`
- `output/os_scan_YYYYMMDD_HHMMSS.json`
- `output/ping_sweep_YYYYMMDD_HHMMSS.json`
- `output/port_scan_YYYYMMDD_HHMMSS.csv`
- `output/vuln_scan_YYYYMMDD_HHMMSS.json`

PCAP files (when capture is enabled) are saved to `./pcaps/` by default:
- `pcaps/DNS_Enumeration_YYYYMMDD_HHMMSS.pcap`
- `pcaps/Host_Discovery_YYYYMMDD_HHMMSS.pcap`
- `pcaps/OS_Scan_YYYYMMDD_HHMMSS.pcap`
- `pcaps/Ping_Sweep_YYYYMMDD_HHMMSS.pcap`
- `pcaps/Port_Scan_YYYYMMDD_HHMMSS.pcap`
- `pcaps/Vuln_Scan_YYYYMMDD_HHMMSS.pcap`

---

## Project Structure

```
reconnaissance/
├── tools/
│   ├── dns_enum.py          # DNS enumeration (600+ lines)
│   ├── host_discovery.py    # Host discovery (400+ lines)
│   ├── os_scan.py           # OS fingerprinting (400+ lines)
│   ├── ping_sweep.py        # Ping sweep (300+ lines)
│   ├── port_scan.py         # Port scanning (500+ lines)
│   ├── recon_menu.py        # Interactive terminal menu (900+ lines)
│   ├── recon_utils.py       # Shared utilities (300+ lines)
│   ├── vuln_scan.py         # Vulnerability scanning (600+ lines)
│   └── wireless.py          # Wireless adapter + monitor mode (300+ lines)
├── wordlists/
│   └── subdomains.txt       # Subdomain wordlist
├── docs/
│   └── THEORETICAL_ANALYSIS.md  # Complete theory (3000+ lines)
├── output/
│   └── (scan results saved here)
├── pcaps/
│   └── (PCAP captures saved here)
└── README.md
```

---

## Installation

```bash
# Core dependencies
pip3 install scapy dnspython

# Wireless support
sudo apt install aircrack-ng wireless-tools iw

# Optional for faster scanning
pip3 install netifaces
```

---

## Evasion Techniques

Each tool includes evasion options:

| Technique | Tool | Option |
|-----------|------|--------|
| Randomized scan order | ping_sweep | `--randomize` |
| SYN half-open (no logs) | port_scan | `-s syn` |
| FIN/XMAS stealth scans | port_scan | `-s fin` / `-s xmas` |
| Configurable timeout | all tools | `--timeout` |
| Configurable threads | all tools | `--threads` |

---

## Standalone

This toolkit is completely independent.
No dependencies on other attack toolkits.
Self-contained utilities, documentation, and wordlists.

**Use responsibly. Authorized security testing only.**
