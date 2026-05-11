#!/usr/bin/env python3
"""
OS Scanner — Active & Passive OS Fingerprinting
TCP/IP stack analysis, TTL, window size, TCP options, banner grabbing
"""

import sys, os, argparse, socket, struct, time, threading
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))
from utils.recon_utils import (ScanResults, grab_banner, guess_os_from_ttl,
                                guess_os_from_banner, expand_cidr)

try:
    from scapy.all import IP, TCP, ICMP, sr1, conf
    conf.verb = 0
    SCAPY = True
except ImportError:
    SCAPY = False


# ── OS Fingerprint Database ────────────────────────────────────────── #

OS_SIGNATURES = {
    # (ttl_range, window_size, options_order) → OS
    'linux_modern':   {'ttl': (63, 64),  'window': [5840, 29200, 65535], 'name': 'Linux (Kernel 3.x+)'},
    'linux_old':      {'ttl': (63, 64),  'window': [5840],               'name': 'Linux (Kernel 2.x)'},
    'windows_10':     {'ttl': (127,128), 'window': [8192, 65535],        'name': 'Windows 10/11/Server 2019+'},
    'windows_7':      {'ttl': (127,128), 'window': [8192],               'name': 'Windows 7/Server 2008'},
    'windows_xp':     {'ttl': (127,128), 'window': [65535],              'name': 'Windows XP/2003'},
    'macos_modern':   {'ttl': (63, 64),  'window': [65535],              'name': 'macOS (10.13+)'},
    'freebsd':        {'ttl': (63, 64),  'window': [65535],              'name': 'FreeBSD'},
    'openbsd':        {'ttl': (254,255), 'window': [16384],              'name': 'OpenBSD'},
    'cisco_ios':      {'ttl': (254,255), 'window': [4128],               'name': 'Cisco IOS'},
    'solaris':        {'ttl': (254,255), 'window': [8760, 49152],        'name': 'Solaris/SunOS'},
    'android':        {'ttl': (63, 64),  'window': [65535],              'name': 'Android'},
}

SERVICE_BANNERS = {
    21:   (b'',              'FTP'),
    22:   (b'',              'SSH'),
    23:   (b'',              'Telnet'),
    25:   (b'EHLO recon\r\n','SMTP'),
    80:   (b'HEAD / HTTP/1.0\r\n\r\n', 'HTTP'),
    110:  (b'',              'POP3'),
    143:  (b'',              'IMAP'),
    443:  (b'HEAD / HTTP/1.0\r\n\r\n', 'HTTPS'),
    3306: (b'',              'MySQL'),
    5432: (b'',              'PostgreSQL'),
    6379: (b'INFO\r\n',     'Redis'),
    27017:(b'',              'MongoDB'),
}


class OSScanner:

    def __init__(self, target, timeout=3):
        self.target  = target
        self.timeout = timeout
        self.results = ScanResults('os_scan', target)

    # ── TTL-based fingerprinting ─────────────────────────────────────── #

    def ttl_fingerprint(self):
        """Send ICMP echo and analyse TTL of response"""
        if not SCAPY:
            return self._ttl_via_ping()

        print(f"\n[*] TTL fingerprinting → {self.target}")
        pkt  = IP(dst=self.target) / ICMP()
        resp = sr1(pkt, timeout=self.timeout, verbose=0)

        if resp:
            ttl     = resp[IP].ttl
            os_hint = guess_os_from_ttl(ttl)
            print(f"  [TTL]  {ttl} → {os_hint}")
            return ttl, os_hint
        return None, None

    def _ttl_via_ping(self):
        """Parse TTL from system ping output"""
        import subprocess, re, platform
        flag = '-n' if platform.system().lower() == 'windows' else '-c'
        out  = subprocess.run(['ping', flag, '3', self.target],
                              capture_output=True, text=True).stdout
        m = re.search(r'ttl=(\d+)', out, re.IGNORECASE)
        if m:
            ttl     = int(m.group(1))
            os_hint = guess_os_from_ttl(ttl)
            print(f"  [TTL]  {ttl} → {os_hint}")
            return ttl, os_hint
        return None, None

    # ── TCP stack fingerprinting ─────────────────────────────────────── #

    def tcp_fingerprint(self, port=80):
        """
        Analyse TCP SYN-ACK to fingerprint OS.
        Examines: window size, TCP options, DF bit, TTL
        """
        if not SCAPY:
            print("[!] TCP fingerprint requires Scapy")
            return None

        print(f"\n[*] TCP stack fingerprinting → {self.target}:{port}")

        pkt  = IP(dst=self.target, ttl=64) / TCP(
            dport=port,
            flags='S',
            window=65535,
            options=[('MSS', 1460), ('SAckOK', b''),
                     ('Timestamp', (0, 0)), ('NOP', None),
                     ('WScale', 7)]
        )
        resp = sr1(pkt, timeout=self.timeout, verbose=0)

        if not resp or TCP not in resp:
            print(f"  [-] No TCP response on port {port}")
            return None

        tcp  = resp[TCP]
        ip   = resp[IP]

        window  = tcp.window
        ttl     = ip.ttl
        df      = bool(ip.flags & 0x2)
        options = {opt[0]: opt[1] for opt in (tcp.options or [])}

        print(f"  [TCP]  Window: {window}  TTL: {ttl}  DF: {df}")
        print(f"  [OPT]  Options: {list(options.keys())}")

        os_guess = self._match_os(ttl, window, options)
        print(f"  [OS]   Best match: {os_guess}")

        result = {
            'ip': self.target, 'port': port,
            'ttl': ttl, 'window': window, 'df': df,
            'tcp_options': str(list(options.keys())),
            'os_guess': os_guess,
        }
        self.results.add(result)
        return result

    def _match_os(self, ttl, window, options):
        """Match fingerprint against signature database"""
        candidates = []

        for name, sig in OS_SIGNATURES.items():
            ttl_min, ttl_max = sig['ttl']
            if ttl_min <= ttl <= ttl_max:
                if window in sig['window']:
                    candidates.append((sig['name'], 2))
                else:
                    candidates.append((sig['name'], 1))

        if not candidates:
            return guess_os_from_ttl(ttl)

        candidates.sort(key=lambda x: x[1], reverse=True)
        return candidates[0][0]

    # ── Banner-based fingerprinting ──────────────────────────────────── #

    def banner_fingerprint(self, ports=None):
        """
        Grab banners from open ports and identify OS/service/version.
        """
        if ports is None:
            ports = list(SERVICE_BANNERS.keys())

        print(f"\n[*] Banner fingerprinting → {self.target} ({len(ports)} ports)")
        found = []

        for port in ports:
            probe, svc_name = SERVICE_BANNERS.get(port, (b'', 'unknown'))
            banner = grab_banner(self.target, port, self.timeout, probe)

            if banner:
                os_hint = guess_os_from_banner(banner)
                clean   = banner.replace('\r','').replace('\n',' ')[:80]

                print(f"  [{port:5d}] {svc_name:<10}  {clean}")
                if os_hint:
                    print(f"         OS hint: {os_hint}")

                result = {
                    'ip':       self.target,
                    'port':     port,
                    'service':  svc_name,
                    'banner':   clean,
                    'os_hint':  os_hint or '',
                }
                found.append(result)
                self.results.add(result)

        return found

    # ── ICMP quirks ──────────────────────────────────────────────────── #

    def icmp_quirks(self):
        """
        Send edge-case ICMP packets and analyse responses.
        Different OS reply differently to unusual ICMP.
        """
        if not SCAPY:
            return

        print(f"\n[*] ICMP quirk probes → {self.target}")

        # Probe 1: ICMP timestamp request (type 13)
        pkt  = IP(dst=self.target) / ICMP(type=13)
        resp = sr1(pkt, timeout=self.timeout, verbose=0)
        if resp:
            print(f"  [ICMP-13] Timestamp response — host responds to type 13")

        # Probe 2: ICMP address mask (type 17)
        pkt  = IP(dst=self.target) / ICMP(type=17)
        resp = sr1(pkt, timeout=self.timeout, verbose=0)
        if resp:
            print(f"  [ICMP-17] Address mask response — possibly old Unix/Cisco")

        # Probe 3: Large ICMP with DF bit
        pkt  = IP(dst=self.target, flags='DF') / ICMP() / (b'X' * 1400)
        resp = sr1(pkt, timeout=self.timeout, verbose=0)
        if resp and ICMP in resp:
            if resp[ICMP].type == 3:  # Destination Unreachable
                print(f"  [ICMP-DF] DF fragmentation response — routing device detected")

    # ── Full scan ────────────────────────────────────────────────────── #

    def run_full(self, ports=None):
        """Run all OS fingerprinting techniques"""
        print(f"\n{'='*55}")
        print(f"  OS Scan — {self.target}")
        print(f"{'='*55}")

        ttl, ttl_os = self.ttl_fingerprint()

        tcp_result = None
        for port in [80, 443, 22, 8080]:
            tcp_result = self.tcp_fingerprint(port)
            if tcp_result:
                break

        banners = self.banner_fingerprint(ports)
        self.icmp_quirks()

        # Consolidate guess
        guesses = []
        if ttl_os:
            guesses.append(ttl_os)
        if tcp_result:
            guesses.append(tcp_result['os_guess'])
        for b in banners:
            if b.get('os_hint'):
                guesses.append(b['os_hint'])

        final_guess = max(set(guesses), key=guesses.count) if guesses else 'Unknown'

        print(f"\n  [RESULT] Most likely OS: {final_guess}")

        self.results.stats = {
            'target':       self.target,
            'ttl':          ttl or 'N/A',
            'ttl_os_hint':  ttl_os or 'N/A',
            'final_guess':  final_guess,
            'banners_found': len(banners),
        }
        self.results.print_summary()
        self.results.to_json()

        return final_guess


def main():
    parser = argparse.ArgumentParser(description='OS Scanner')
    parser.add_argument('-t', '--target',  required=True)
    parser.add_argument('--timeout',       type=int, default=3)
    parser.add_argument('--ttl-only',      action='store_true')
    parser.add_argument('--banner-only',   action='store_true')
    parser.add_argument('--tcp-only',      action='store_true')
    parser.add_argument('-p', '--ports',   help='Comma-separated ports for banner scan')
    a = parser.parse_args()

    ports = [int(p) for p in a.ports.split(',')] if a.ports else None
    scanner = OSScanner(a.target, a.timeout)

    if a.ttl_only:
        scanner.ttl_fingerprint()
    elif a.banner_only:
        scanner.banner_fingerprint(ports)
    elif a.tcp_only:
        scanner.tcp_fingerprint()
    else:
        scanner.run_full(ports)


if __name__ == '__main__':
    main()
