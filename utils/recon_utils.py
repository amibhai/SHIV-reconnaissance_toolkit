#!/usr/bin/env python3
"""
Reconnaissance Toolkit - Shared Utilities
Output formatting, network helpers, result storage, reporting
"""

import socket
import ipaddress
import json
import csv
import os
import time
import random
import struct
from datetime import datetime


# ──────────────────────────────────────────────
# Network helpers
# ──────────────────────────────────────────────

def resolve(host):
    """Resolve hostname to IP, return None on failure"""
    try:
        return socket.gethostbyname(host)
    except socket.gaierror:
        return None


def reverse_dns(ip):
    """Reverse DNS lookup"""
    try:
        return socket.gethostbyaddr(ip)[0]
    except Exception:
        return None


def expand_cidr(cidr):
    """Expand CIDR notation to list of host IPs"""
    try:
        net = ipaddress.ip_network(cidr, strict=False)
        return [str(h) for h in net.hosts()]
    except ValueError as e:
        print(f"[!] Invalid CIDR: {e}")
        return []


def ip_range(start_ip, end_ip):
    """Generate IPs between start and end (inclusive)"""
    start = struct.unpack('>I', socket.inet_aton(start_ip))[0]
    end   = struct.unpack('>I', socket.inet_aton(end_ip))[0]
    for ip_int in range(start, end + 1):
        yield socket.inet_ntoa(struct.pack('>I', ip_int))


def is_valid_ip(ip):
    try:
        ipaddress.ip_address(ip)
        return True
    except ValueError:
        return False


def is_valid_port(port):
    return isinstance(port, int) and 1 <= port <= 65535


def get_service_name(port, proto='tcp'):
    try:
        return socket.getservbyport(port, proto)
    except Exception:
        return 'unknown'


def get_random_delay(min_ms=50, max_ms=500):
    """Return random delay in seconds for evasion"""
    return random.uniform(min_ms / 1000, max_ms / 1000)


# ──────────────────────────────────────────────
# Banner grabbing
# ──────────────────────────────────────────────

def grab_banner(host, port, timeout=3, send_probe=None):
    """
    Grab service banner from open port.
    
    Args:
        host: Target IP
        port: Target port
        timeout: Socket timeout
        send_probe: Optional bytes to send before reading
    
    Returns:
        Banner string or None
    """
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(timeout)
        sock.connect((host, port))

        if send_probe:
            sock.sendall(send_probe)
        else:
            # Generic probes for common services
            probes = {
                21:   b'',             # FTP sends banner on connect
                22:   b'',             # SSH sends banner on connect
                25:   b'EHLO test\r\n',
                80:   b'HEAD / HTTP/1.0\r\n\r\n',
                110:  b'',             # POP3
                143:  b'',             # IMAP
                443:  b'HEAD / HTTP/1.0\r\n\r\n',
                3306: b'',             # MySQL sends banner on connect
            }
            probe = probes.get(port, b'')
            if probe:
                sock.sendall(probe)

        banner = sock.recv(1024).decode('utf-8', errors='replace').strip()
        sock.close()
        return banner
    except Exception:
        return None


# ──────────────────────────────────────────────
# OS fingerprinting helpers
# ──────────────────────────────────────────────

def guess_os_from_ttl(ttl):
    """Guess OS from TTL value"""
    if ttl <= 64:
        return 'Linux/Unix/Android'
    elif ttl <= 128:
        return 'Windows'
    elif ttl <= 255:
        return 'Cisco/Solaris/FreeBSD'
    return 'Unknown'


def guess_os_from_banner(banner):
    """Guess OS/service from banner string"""
    if not banner:
        return None
    b = banner.lower()

    checks = [
        ('ubuntu',   'Linux (Ubuntu)'),
        ('debian',   'Linux (Debian)'),
        ('centos',   'Linux (CentOS)'),
        ('fedora',   'Linux (Fedora)'),
        ('freebsd',  'FreeBSD'),
        ('windows',  'Windows'),
        ('microsoft','Windows'),
        ('cisco',    'Cisco IOS'),
        ('openssh',  'OpenSSH'),
        ('apache',   'Apache HTTP'),
        ('nginx',    'nginx'),
        ('iis',      'Microsoft IIS'),
        ('vsftpd',   'vsftpd (Linux)'),
        ('proftpd',  'ProFTPD (Linux)'),
        ('filezilla','FileZilla (Windows)'),
    ]

    for keyword, result in checks:
        if keyword in b:
            return result
    return None


# ──────────────────────────────────────────────
# Result storage
# ──────────────────────────────────────────────

class ScanResults:
    """Store, display, and export scan results"""

    def __init__(self, scan_type, target):
        self.scan_type   = scan_type
        self.target      = target
        self.start_time  = datetime.now()
        self.results     = []
        self.stats       = {}
        os.makedirs('output', exist_ok=True)

    def add(self, data: dict):
        data['timestamp'] = datetime.now().isoformat()
        self.results.append(data)

    def get_count(self):
        return len(self.results)

    # ---- Display helpers ---- #

    def print_host_open(self, ip, hostname=None, extra=''):
        tag  = f" ({hostname})" if hostname else ''
        tail = f" {extra}" if extra else ''
        print(f"  [+] {ip}{tag}{tail}")

    def print_port_open(self, ip, port, proto='tcp', service='', banner=''):
        svc = f"  {service}" if service else ''
        bnr = f"  |  {banner[:60]}" if banner else ''
        print(f"  [OPEN]  {ip}:{port}/{proto}{svc}{bnr}")

    def print_vuln(self, ip, port, vuln_id, severity, description):
        icons = {'critical': '🔴', 'high': '🟠', 'medium': '🟡',
                 'low': '🔵', 'info': '⚪'}
        icon = icons.get(severity.lower(), '⚪')
        print(f"  {icon} [{severity.upper()}] {ip}:{port} — {vuln_id}: {description}")

    # ---- Export methods ---- #

    def to_json(self, filename=None):
        ts  = self.start_time.strftime('%Y%m%d_%H%M%S')
        fn  = filename or f"output/{self.scan_type}_{ts}.json"
        out = {
            'scan_type':  self.scan_type,
            'target':     self.target,
            'start_time': self.start_time.isoformat(),
            'end_time':   datetime.now().isoformat(),
            'stats':      self.stats,
            'results':    self.results,
        }
        with open(fn, 'w') as f:
            json.dump(out, f, indent=2)
        print(f"\n[+] JSON saved: {fn}")
        return fn

    def to_csv(self, filename=None):
        if not self.results:
            return None
        ts  = self.start_time.strftime('%Y%m%d_%H%M%S')
        fn  = filename or f"output/{self.scan_type}_{ts}.csv"
        with open(fn, 'w', newline='') as f:
            writer = csv.DictWriter(f, fieldnames=self.results[0].keys())
            writer.writeheader()
            writer.writerows(self.results)
        print(f"[+] CSV saved:  {fn}")
        return fn

    def to_txt(self, filename=None):
        ts = self.start_time.strftime('%Y%m%d_%H%M%S')
        fn = filename or f"output/{self.scan_type}_{ts}.txt"
        with open(fn, 'w') as f:
            f.write(f"Scan Type : {self.scan_type}\n")
            f.write(f"Target    : {self.target}\n")
            f.write(f"Started   : {self.start_time}\n")
            f.write(f"Finished  : {datetime.now()}\n")
            f.write("="*60 + "\n\n")
            for r in self.results:
                f.write(str(r) + "\n")
        print(f"[+] TXT saved:  {fn}")
        return fn

    def print_summary(self):
        elapsed = (datetime.now() - self.start_time).total_seconds()
        print(f"\n{'='*55}")
        print(f"  {self.scan_type} — Summary")
        print(f"{'='*55}")
        print(f"  Target  : {self.target}")
        print(f"  Results : {len(self.results)}")
        print(f"  Elapsed : {elapsed:.2f}s")
        for k, v in self.stats.items():
            print(f"  {k:<10}: {v}")
        print(f"{'='*55}")


# ──────────────────────────────────────────────
# Progress display
# ──────────────────────────────────────────────

class Progress:
    """Simple inline progress indicator"""

    def __init__(self, total, label='Progress'):
        self.total   = total
        self.current = 0
        self.label   = label
        self.start   = time.time()

    def update(self, current=None, extra=''):
        if current is not None:
            self.current = current
        else:
            self.current += 1

        pct     = (self.current / self.total * 100) if self.total else 0
        elapsed = time.time() - self.start
        rate    = self.current / elapsed if elapsed > 0 else 0
        eta     = (self.total - self.current) / rate if rate > 0 else 0

        bar_len  = 25
        filled   = int(bar_len * pct / 100)
        bar      = '█' * filled + '░' * (bar_len - filled)

        print(f"\r  [{bar}] {pct:5.1f}%  {self.current}/{self.total}"
              f"  {rate:.1f}/s  ETA:{eta:.0f}s  {extra}",
              end='', flush=True)

    def done(self):
        elapsed = time.time() - self.start
        print(f"\r  [{'█'*25}] 100.0%  {self.total}/{self.total}"
              f"  Done in {elapsed:.2f}s                    ")
