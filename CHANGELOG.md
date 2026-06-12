# Changelog

All notable changes to Recon Toolkit are documented here.

---

## [2.1.0] — 2026-06-12

### Added
- **Advanced Recon Modules**
  - `http_probe.py` — WAF/CDN/tech fingerprint, security headers, path discovery
  - `tls_probe.py` — Cipher enum, cert chain, JA3S, CT logs
  - `smb_enum.py` — NetBIOS, dialect negotiation, EternalBlue/SMBGhost pre-checks
  - `snmp_enum.py` — Community brute, sysInfo, ARP, routes, process list
  - `async_scan.py` — 10k–50k ports/s asyncio scanner, no root required
- **Menu System Updates**
  - Updated `menu.py` and `tools/recon_menu.py` to include the 5 new advanced modules
  - Separated menu into "CORE RECONNAISSANCE" and "ADVANCED MODULES" sections

---

## [2.0.1] — 2026-06-12

### Added
- **wifi\_down-style banner system** (`recon/core/logger.py`)
  - `RECON` block art revealed row-by-row with 0.04 s scan-line delay
  - Tri-zone cyan colour gradient (color 51 → 87 bold → 50) with corner-char highlights
  - `── made by Swastik ──` typed character-by-character at 0.04 s/char
  - Random hacker quote pool (9 quotes) with `❝❞` typewriter formatting
  - Plain typewriter legal disclaimer (no Rich Panel)
  - Segment-by-segment status bar: `◈ toolkit: recon v2.0  ◈ status: ready  ◈ <time>`
  - Pulsing `[ Press ENTER to launch recon-toolkit ]` prompt (3-cycle color pulse 51 → 87 → 123 → 87 → 51)
  - Screen cleared after ENTER — identical flow to wifi\_down
- `print_compact_header(target?)` — one-line `recon-toolkit  ◈  <time>  ◈  <target>` for per-screen use
- `print_compact_header` added to `__all__` in logger module

### Changed
- `tools/recon_menu.py` — full wifi\_down launch pattern applied
  - Full `print_banner()` called **once** at startup before the menu loop
  - Per-screen `banner()` function replaced with `print_compact_header()` (clears screen + compact header)
  - Root dir added to `sys.path` so `recon.core.logger` is importable from `tools/`
  - Graceful fallback to plain ANSI header if Rich is unavailable
- `recon/core/logger.py` — `print_banner()` completely rewritten
  - Removed simple `console.print(banner_text)` + Rich Panel approach
  - Now orchestrates the full wifi\_down-style sequence
  - All banner output routed through a single `sys.stdout` stream (stdout reconfigured to UTF-8); eliminates the dual-TextIOWrapper conflict that caused incorrect rendering on Windows
  - Removed unused `Panel` import

### Fixed
- Unicode box-drawing characters now render correctly on Windows (VS Code integrated terminal, Windows Terminal) via `sys.stdout.reconfigure(encoding='utf-8')`
- Removed stale `logger.cpython-312.pyc` cache that could serve the old banner

---

## [2.0.0] — 2026-06-02

### Added
- **Typer CLI** (`recon.py`) with 8 subcommands: `dns`, `discover`, `os`, `portscan`, `vulnscan`, `wireless`, `full`, `privcheck`
- **CLI entry point** (`e8d1a8f`) — `recon.py` wired to all module subcommands
- **Report templates** (`c9974f1`) — Jinja2 dark-theme HTML template in `recon/reports/`
- **Module `__init__` files** — clean package structure under `recon/`
- **Comprehensive test suite** (`4616b88`) — 62 tests across config, DNS, ports, vulns, output; all passing
- **Reconnaissance data files** (`e3be395`)
  - `cve_db.json` — 55 CVE entries (Apache, OpenSSH, Log4j, Exchange, F5, Citrix, VMware, ProxyLogon, ProxyShell, BlueKeep, EternalBlue…)
  - `service_probes.json` — 35+ service identification probes (HTTP, SSH, Redis, Elasticsearch, Docker, Kubernetes…)
  - `default_creds.json` — 13 credential sets (FTP, SSH, HTTP basic, Redis, MySQL, MongoDB…)
  - `wordlists/subdomains_top5000.txt`, `wordlists/dns_resolvers.txt`
- **Wireless & PCAP modules** (`67616a1`)
  - `recon/modules/wireless.py` — interface discovery, monitor mode, channel hopping, 802.11 frame parsing
  - `recon/modules/pcap_capture.py` — AsyncSniffer, ring-buffer, thread-safe PCAP writer
- **Vulnerability scanning module** (`f269f76`) — CVE banner matching, SSL/TLS audit, default credential tests, misconfiguration detection
- **Port scanning module** (`e1fad01`) — SYN / Connect / FIN / XMAS / NULL / ACK / UDP scan types with service detection and evasion levels 0–3
- **OS fingerprinting module** (`ab9d5a2`) — 15 OS signatures, TTL analysis, TCP stack fingerprint, banner grabbing, ICMP quirk probes
- **Host discovery module** (`786e833`) — ARP sweep, ICMP echo, TCP connect, UDP probe with OUI vendor lookup
- **DNS enumeration module** (`cd746a9`) — AXFR zone transfer, wildcard detection, subdomain brute-force, record types, DNSSEC, reverse sweep
- **Core infrastructure** (`26fad97`)
  - `recon/core/config.py` — Pydantic v2 settings with TOML support
  - `recon/core/logger.py` — Rich console, RichHandler, JSON Lines file output, `make_progress()`, `print_findings_table()`
  - `recon/core/output.py` — `ScanReport` dataclass, `OutputManager` (JSON / CSV / HTML / PCAP)
  - `recon/core/privilege.py` — root / CAP\_NET\_RAW detection with feature availability matrix

### Changed
- `tools/recon_menu.py` updated to import from the new `recon` package structure

---

## [1.0.0] — 2026-05-11

### Added
- Initial commit — Reconnaissance Toolkit v1.0
- `tools/recon_menu.py` — interactive menu-driven interface with ANSI colour helpers
- Standalone tool scripts under `tools/`: `dns_enum.py`, `host_discovery.py`, `os_scan.py`, `ping_sweep.py`, `port_scan.py`, `vuln_scan.py`, `wireless.py`
- Utility helpers: `utils/recon_utils.py`, `utils/wireless.py`
- Inline PCAP capture engine with `PCAPCapture` class
- `C` colour helper class for ANSI terminal output
