#!/usr/bin/env python3
"""
Port Scanner
SYN / Connect / UDP / FIN / XMAS / ACK scans
Service version detection, banner grabbing, output in multiple formats
"""

import sys, os, argparse, threading, queue, socket, time, random
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))
from utils.recon_utils import (ScanResults, Progress, grab_banner,
                                get_service_name, guess_os_from_banner)

try:
    from scapy.all import IP, TCP, UDP, ICMP, sr1, conf, RandShort
    conf.verb = 0
    SCAPY = True
except ImportError:
    SCAPY = False

# Well-known port list for quick scans
TOP_100_PORTS = [
    21, 22, 23, 25, 53, 80, 110, 111, 119, 135, 139, 143, 161, 179,
    194, 443, 445, 465, 514, 515, 587, 631, 993, 995, 1080, 1194, 1433,
    1521, 1723, 2049, 2121, 2222, 3306, 3389, 4444, 5432, 5900, 5901,
    6379, 6667, 7070, 8000, 8008, 8080, 8088, 8443, 8888, 9000, 9090,
    9200, 9300, 10000, 11211, 27017, 28017, 50000,
]

TOP_20_PORTS = [21, 22, 23, 25, 53, 80, 110, 135, 139, 143,
                443, 445, 3306, 3389, 5432, 5900, 6379, 8080, 8443, 27017]


class PortScanner:

    def __init__(self, target, threads=200, timeout=1.0, scan_type='syn'):
        self.target    = target
        self.threads   = threads
        self.timeout   = timeout
        self.scan_type = scan_type
        self.results   = ScanResults('port_scan', target)
        self.lock      = threading.Lock()
        self.open_ports= []

    # ── SYN Scan ─────────────────────────────────────────────────────── #

    def syn_scan(self, port):
        """
        Half-open SYN scan — fastest and stealthiest.
        Requires root / Scapy.
        SYN → SYN-ACK = OPEN
        SYN → RST     = CLOSED
        (no response) = FILTERED
        """
        if not SCAPY:
            return self.connect_scan(port)

        src_port = random.randint(32768, 65535)
        pkt  = IP(dst=self.target) / TCP(sport=src_port, dport=port, flags='S')
        resp = sr1(pkt, timeout=self.timeout, verbose=0)

        if resp is None:
            return 'filtered'
        if resp.haslayer(TCP):
            flags = resp[TCP].flags
            if flags & 0x12:   # SYN-ACK
                # Send RST to close (don't complete handshake)
                rst = IP(dst=self.target) / TCP(
                    sport=src_port, dport=port, flags='R',
                    seq=resp[TCP].ack)
                sr1(rst, timeout=0.5, verbose=0)
                return 'open'
            if flags & 0x14:   # RST-ACK
                return 'closed'
        if resp.haslayer(ICMP):
            if int(resp[ICMP].type) == 3:
                return 'filtered'

        return 'filtered'

    # ── Connect Scan ─────────────────────────────────────────────────── #

    def connect_scan(self, port):
        """
        Full TCP connect scan — no root required.
        Logged by target but most reliable.
        """
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.settimeout(self.timeout)
            result = s.connect_ex((self.target, port))
            s.close()
            if result == 0:
                return 'open'
            if result == 111:
                return 'closed'
            return 'filtered'
        except socket.timeout:
            return 'filtered'
        except Exception:
            return 'error'

    # ── UDP Scan ─────────────────────────────────────────────────────── #

    def udp_scan(self, port):
        """
        UDP scan — slow but essential.
        No response   = open|filtered
        ICMP unreach  = closed
        UDP response  = open
        """
        if not SCAPY:
            return 'open|filtered'

        # Protocol-specific payloads
        payloads = {
            53:  b'\xaa\xbb\x01\x00\x00\x01\x00\x00\x00\x00\x00\x00'
                 b'\x07example\x03com\x00\x00\x01\x00\x01',
            123: b'\x1b' + b'\x00' * 47,
            161: b'\x30\x26\x02\x01\x01\x04\x06public\xa0\x19'
                 b'\x02\x04\x00\x00\x00\x01\x02\x01\x00\x02\x01\x00'
                 b'\x30\x0b\x30\x09\x06\x05+\x06\x01\x02\x01\x05\x00',
            137: b'\xab\xcd\x00\x00\x00\x01\x00\x00\x00\x00\x00\x00'
                 b'\x20CKAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA\x00\x00\x21\x00\x01',
        }
        payload = payloads.get(port, b'\x00' * 8)

        pkt  = IP(dst=self.target) / UDP(dport=port) / payload
        resp = sr1(pkt, timeout=self.timeout, verbose=0)

        if resp is None:
            return 'open|filtered'
        if resp.haslayer(UDP):
            return 'open'
        if resp.haslayer(ICMP) and resp[ICMP].type == 3:
            if resp[ICMP].code == 3:
                return 'closed'
            return 'filtered'

        return 'open|filtered'

    # ── Stealth Scans ────────────────────────────────────────────────── #

    def fin_scan(self, port):
        """FIN scan — evades some firewalls, unreliable on Windows"""
        if not SCAPY:
            return 'unsupported'
        pkt  = IP(dst=self.target) / TCP(dport=port, flags='F')
        resp = sr1(pkt, timeout=self.timeout, verbose=0)
        if resp is None:
            return 'open|filtered'
        if resp.haslayer(TCP) and resp[TCP].flags & 0x04:
            return 'closed'
        return 'filtered'

    def xmas_scan(self, port):
        """XMAS scan (FIN+PSH+URG) — similar to FIN but more distinctive"""
        if not SCAPY:
            return 'unsupported'
        pkt  = IP(dst=self.target) / TCP(dport=port, flags='FPU')
        resp = sr1(pkt, timeout=self.timeout, verbose=0)
        if resp is None:
            return 'open|filtered'
        if resp.haslayer(TCP) and resp[TCP].flags & 0x04:
            return 'closed'
        return 'filtered'

    def ack_scan(self, port):
        """ACK scan — detects firewall rules (not port state)"""
        if not SCAPY:
            return 'unsupported'
        pkt  = IP(dst=self.target) / TCP(dport=port, flags='A')
        resp = sr1(pkt, timeout=self.timeout, verbose=0)
        if resp is None:
            return 'filtered'
        if resp.haslayer(TCP) and resp[TCP].flags & 0x04:
            return 'unfiltered'
        if resp.haslayer(ICMP):
            return 'filtered'
        return 'filtered'

    # ── Service detection ────────────────────────────────────────────── #

    def detect_service(self, port, proto='tcp'):
        """Identify service and grab banner"""
        service = get_service_name(port, proto)
        banner  = None
        version = None

        if proto == 'tcp' and port < 10000:
            banner  = grab_banner(self.target, port, timeout=2)
            if banner:
                version = self._extract_version(banner)
                os_hint = guess_os_from_banner(banner)
                return service, banner[:80], version, os_hint

        return service, banner, version, None

    def _extract_version(self, banner):
        """Extract version string from banner"""
        import re
        patterns = [
            r'(\d+\.\d+[\.\d]*)',       # Generic version numbers
            r'OpenSSH[_\s]([\d.p]+)',    # OpenSSH specific
            r'Apache/([\d.]+)',          # Apache
            r'nginx/([\d.]+)',           # nginx
            r'Microsoft-IIS/([\d.]+)',   # IIS
        ]
        for pattern in patterns:
            m = re.search(pattern, banner, re.IGNORECASE)
            if m:
                return m.group(1)
        return None

    # ── Thread worker ────────────────────────────────────────────────── #

    def _scan_port(self, port, proto='tcp'):
        """Scan single port and record if open"""
        if proto == 'tcp':
            scanners = {
                'syn':     self.syn_scan,
                'connect': self.connect_scan,
                'fin':     self.fin_scan,
                'xmas':    self.xmas_scan,
                'ack':     self.ack_scan,
            }
            scanner = scanners.get(self.scan_type, self.connect_scan)
            state   = scanner(port)
        else:
            state   = self.udp_scan(port)

        if state in ('open', 'open|filtered'):
            service, banner, version, os_hint = self.detect_service(port, proto)

            result = {
                'ip':       self.target,
                'port':     port,
                'proto':    proto,
                'state':    state,
                'service':  service,
                'banner':   banner or '',
                'version':  version or '',
                'os_hint':  os_hint or '',
            }

            with self.lock:
                self.open_ports.append(result)
                self.results.add(result)

                v_str = f"  {version}" if version else ''
                b_str = f"  |  {banner[:50]}" if banner else ''
                print(f"\n  [OPEN]  {self.target}:{port:<6}/{proto:<4}  "
                      f"{service:<14}{v_str}{b_str}")

    # ── Main scan runner ─────────────────────────────────────────────── #

    def scan_ports(self, ports, proto='tcp'):
        """Multi-threaded port scan"""
        scan_label = f"{self.scan_type.upper()} scan" if proto == 'tcp' else 'UDP scan'
        print(f"\n[*] {scan_label} → {self.target}  ({len(ports)} ports, {self.threads} threads)")

        q    = queue.Queue()
        prog = Progress(len(ports), scan_label)

        for p in ports:
            q.put(p)

        def worker():
            while True:
                try:
                    port = q.get(timeout=1)
                except queue.Empty:
                    break
                self._scan_port(port, proto)
                prog.update()
                q.task_done()

        threads = [threading.Thread(target=worker, daemon=True)
                   for _ in range(min(self.threads, len(ports)))]
        for t in threads:
            t.start()
        q.join()
        prog.done()

    def run_full(self, port_range=None, include_udp=False):
        """Full port scan with service detection"""
        print(f"\n{'='*55}")
        print(f"  Port Scan ({self.scan_type.upper()}) — {self.target}")
        print(f"{'='*55}")

        # Determine port list
        if port_range == 'top20':
            tcp_ports = TOP_20_PORTS
        elif port_range == 'top100':
            tcp_ports = TOP_100_PORTS
        elif port_range and '-' in str(port_range):
            start, end = port_range.split('-')
            tcp_ports  = list(range(int(start), int(end)+1))
        elif port_range == 'all':
            tcp_ports  = list(range(1, 65536))
        else:
            tcp_ports  = TOP_100_PORTS

        # TCP scan
        self.scan_ports(tcp_ports, 'tcp')

        # Optional UDP scan
        if include_udp:
            udp_ports = [53, 67, 68, 69, 123, 137, 138, 139, 161, 162,
                         500, 514, 520, 1194, 1900, 4500, 5353]
            self.scan_ports(udp_ports, 'udp')

        # Summary
        self.results.stats = {
            'total_scanned': len(tcp_ports),
            'open_ports':    len(self.open_ports),
        }
        self.results.print_summary()

        if self.open_ports:
            print("\n  Open Ports Summary:")
            for r in sorted(self.open_ports, key=lambda x: x['port']):
                v = f"  {r['version']}" if r['version'] else ''
                print(f"    {r['port']:<6}/{r['proto']:<4}  {r['state']:<16} {r['service']}{v}")

        self.results.to_json()
        self.results.to_csv()

        return self.open_ports


def main():
    parser = argparse.ArgumentParser(description='Port Scanner')
    parser.add_argument('-t', '--target',     required=True)
    parser.add_argument('-s', '--scan-type',
                        choices=['syn','connect','fin','xmas','ack','udp'],
                        default='syn')
    parser.add_argument('-p', '--ports',
                        help='top20 | top100 | all | 1-1024 | 80,443,8080')
    parser.add_argument('--threads',          type=int,   default=200)
    parser.add_argument('--timeout',          type=float, default=1.0)
    parser.add_argument('--udp',              action='store_true')
    a = parser.parse_args()

    scanner = PortScanner(a.target, a.threads, a.timeout, a.scan_type)

    # Handle comma-separated ports
    if a.ports and ',' in a.ports:
        ports = [int(p) for p in a.ports.split(',')]
        scanner.scan_ports(ports, 'udp' if a.scan_type == 'udp' else 'tcp')
    else:
        scanner.run_full(a.ports or 'top100', include_udp=a.udp)


if __name__ == '__main__':
    main()
