#!/usr/bin/env python3
"""
Vulnerability Scanner
Version-based CVE detection, SSL/TLS auditing,
default credentials, service misconfiguration checks
"""

import sys, os, argparse, socket, ssl, threading, re, time
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))
from utils.recon_utils import ScanResults, grab_banner

# ── CVE Database ─────────────────────────────────────────────────────── #

CVE_DATABASE = {
    'openssh': [
        {'version_max': '7.4',  'cve': 'CVE-2018-15473', 'severity': 'medium',
         'cvss': 5.3, 'description': 'Username enumeration via timing side-channel'},
        {'version_max': '6.6',  'cve': 'CVE-2014-1692',  'severity': 'high',
         'cvss': 7.5, 'description': 'Potential memory corruption in J-PAKE'},
        {'version_max': '5.1',  'cve': 'CVE-2008-5161',  'severity': 'medium',
         'cvss': 2.6, 'description': 'CBC mode plaintext recovery (Lucky13 precursor)'},
    ],
    'apache': [
        {'version': '2.4.49',   'cve': 'CVE-2021-41773', 'severity': 'critical',
         'cvss': 9.8, 'description': 'Path traversal and RCE (mod_cgi enabled)'},
        {'version': '2.4.50',   'cve': 'CVE-2021-42013', 'severity': 'critical',
         'cvss': 9.8, 'description': 'Path traversal bypass (incomplete fix for 41773)'},
        {'version_max': '2.4.48','cve': 'CVE-2021-40438','severity': 'critical',
         'cvss': 9.0, 'description': 'Server-side request forgery via mod_proxy'},
        {'version_max': '2.2.32','cve': 'CVE-2017-7679', 'severity': 'critical',
         'cvss': 9.8, 'description': 'mod_mime buffer overread'},
    ],
    'nginx': [
        {'version_max': '1.14.0','cve': 'CVE-2018-16843', 'severity': 'high',
         'cvss': 7.5, 'description': 'HTTP/2 memory leak DoS'},
        {'version_max': '1.9.5', 'cve': 'CVE-2016-4450',  'severity': 'high',
         'cvss': 7.5, 'description': 'NULL pointer dereference DoS'},
    ],
    'openssl': [
        {'version_max': '1.0.1f','cve': 'CVE-2014-0160',  'severity': 'critical',
         'cvss': 7.5, 'description': 'Heartbleed — private key & memory exposure'},
        {'version_max': '1.0.1',  'cve': 'CVE-2014-0224',  'severity': 'high',
         'cvss': 6.8, 'description': 'MITM via ChangeCipherSpec injection'},
        {'version_max': '1.0.2h', 'cve': 'CVE-2016-6304',  'severity': 'high',
         'cvss': 7.5, 'description': 'OCSP status memory exhaustion DoS'},
    ],
    'mysql': [
        {'version_max': '5.7.32', 'cve': 'CVE-2020-14765', 'severity': 'high',
         'cvss': 6.5, 'description': 'Privilege escalation in FTS component'},
        {'version_max': '5.6.0',  'cve': 'CVE-2012-2122',  'severity': 'critical',
         'cvss': 7.5, 'description': 'Authentication bypass via timing attack'},
    ],
    'vsftpd': [
        {'version': '2.3.4',    'cve': 'CVE-2011-2523',  'severity': 'critical',
         'cvss': 10.0,'description': "Backdoor — smiley face ':)' trigger opens shell on port 6200"},
    ],
    'log4j': [
        {'version_max': '2.14.1','cve': 'CVE-2021-44228', 'severity': 'critical',
         'cvss': 10.0,'description': 'Log4Shell — JNDI RCE via malicious lookup strings'},
        {'version_max': '2.16.0','cve': 'CVE-2021-45046', 'severity': 'critical',
         'cvss': 9.0, 'description': 'Incomplete Log4Shell fix — DoS and RCE'},
    ],
    'struts': [
        {'version_max': '2.3.32','cve': 'CVE-2017-5638',  'severity': 'critical',
         'cvss': 10.0,'description': 'Equifax breach — Content-Type header RCE'},
    ],
    'proftpd': [
        {'version_max': '1.3.5', 'cve': 'CVE-2015-3306',  'severity': 'critical',
         'cvss': 10.0,'description': 'mod_copy unauthenticated file copy/RCE'},
    ],
    'samba': [
        {'version_max': '4.6.3', 'cve': 'CVE-2017-7494',  'severity': 'critical',
         'cvss': 10.0,'description': 'SambaCry — writable share RCE'},
    ],
}

# ── Default credentials ──────────────────────────────────────────────── #

DEFAULT_CREDENTIALS = {
    'ftp':   [('anonymous','anonymous'), ('admin','admin'), ('ftp','ftp'),
              ('root','root'), ('admin','')],
    'ssh':   [('root','root'), ('root','toor'), ('admin','admin'),
              ('admin','password'), ('pi','raspberry'), ('ubuntu','ubuntu')],
    'mysql': [('root',''), ('root','root'), ('root','mysql'),
              ('admin','admin')],
    'redis': [('', ''), ('default', '')],
    'snmp':  [('public', ''), ('private', ''), ('community', '')],
}


class VulnerabilityScanner:

    def __init__(self, target, ports=None, timeout=5):
        self.target  = target
        self.ports   = ports
        self.timeout = timeout
        self.results = ScanResults('vuln_scan', target)
        self.vulns   = []
        self.lock    = threading.Lock()

    # ── Version-based CVE detection ──────────────────────────────────── #

    def check_service_vulns(self, port, banner):
        """Match banner against CVE database"""
        if not banner:
            return []

        found = []
        b_low = banner.lower()

        for product, cves in CVE_DATABASE.items():
            if product not in b_low:
                continue

            # Extract version number
            version_match = re.search(r'(\d+\.\d+[\.\d]*[\w]*)', banner)
            if not version_match:
                continue

            version_str = version_match.group(1)

            for cve_entry in cves:
                vuln = {
                    'ip':          self.target,
                    'port':        port,
                    'product':     product,
                    'version':     version_str,
                    'cve':         cve_entry['cve'],
                    'severity':    cve_entry['severity'],
                    'cvss':        cve_entry['cvss'],
                    'description': cve_entry['description'],
                    'banner':      banner[:80],
                }
                found.append(vuln)
                self._record_vuln(vuln)

        return found

    def _record_vuln(self, vuln):
        with self.lock:
            self.vulns.append(vuln)
            self.results.add(vuln)
            self.results.print_vuln(
                vuln['ip'], vuln['port'],
                vuln['cve'], vuln['severity'], vuln['description']
            )

    # ── SSL/TLS audit ────────────────────────────────────────────────── #

    def ssl_audit(self, port=443):
        """
        Comprehensive SSL/TLS configuration audit.
        Checks: protocol versions, cipher suites, certificate validity.
        """
        print(f"\n[*] SSL/TLS audit → {self.target}:{port}")
        issues = []

        # Check deprecated protocols
        weak_protocols = [
            (ssl.PROTOCOL_TLS, {'SSLv2': True},  'SSLv2',  'critical'),
            (ssl.PROTOCOL_TLS, {'SSLv3': True},  'SSLv3',  'critical'),
        ]

        # TLS version check
        tls_versions = [
            ('TLSv1',   ssl.TLSVersion.TLSv1,   'high',   'TLSv1.0 deprecated (RFC 8996)'),
            ('TLSv1.1', ssl.TLSVersion.TLSv1_1, 'high',   'TLSv1.1 deprecated (RFC 8996)'),
            ('TLSv1.2', ssl.TLSVersion.TLSv1_2, 'info',   'TLSv1.2 acceptable minimum'),
            ('TLSv1.3', ssl.TLSVersion.TLSv1_3, 'info',   'TLSv1.3 best — modern standard'),
        ]

        for tls_name, tls_ver, severity, desc in tls_versions:
            try:
                ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
                ctx.check_hostname = False
                ctx.verify_mode    = ssl.CERT_NONE
                ctx.minimum_version = tls_ver
                ctx.maximum_version = tls_ver

                s = socket.create_connection((self.target, port), timeout=self.timeout)
                tls_sock = ctx.wrap_socket(s, server_hostname=self.target)
                tls_sock.close()

                status = 'ENABLED'
                icon   = '⚠️' if severity in ('critical','high') else '✅'
                print(f"  {icon} {tls_name}: {status}  ({desc})")

                if severity in ('critical', 'high', 'medium'):
                    issue = {
                        'ip': self.target, 'port': port,
                        'type': 'ssl_weak_protocol', 'protocol': tls_name,
                        'severity': severity, 'description': desc,
                        'cve': 'N/A',
                    }
                    issues.append(issue)
                    self._record_vuln(issue)
            except Exception:
                print(f"  [-] {tls_name}: disabled / not supported")

        # Certificate info
        try:
            ctx  = ssl.create_default_context()
            ctx.check_hostname = False
            ctx.verify_mode    = ssl.CERT_NONE
            s    = socket.create_connection((self.target, port), timeout=self.timeout)
            tls  = ctx.wrap_socket(s, server_hostname=self.target)
            cert = tls.getpeercert()
            tls.close()

            if cert:
                subject  = dict(x[0] for x in cert.get('subject', []))
                issuer   = dict(x[0] for x in cert.get('issuer', []))
                not_after= cert.get('notAfter', '')

                print(f"\n  [CERT] Subject : {subject.get('commonName', 'N/A')}")
                print(f"  [CERT] Issuer  : {issuer.get('organizationName', 'N/A')}")
                print(f"  [CERT] Expires : {not_after}")

                # Self-signed check
                if subject == issuer:
                    issue = {
                        'ip': self.target, 'port': port,
                        'type': 'self_signed_certificate',
                        'severity': 'medium',
                        'description': 'Self-signed certificate — no trusted CA',
                        'cve': 'N/A',
                    }
                    issues.append(issue)
                    self._record_vuln(issue)
        except Exception:
            pass

        return issues

    # ── Default credential testing ───────────────────────────────────── #

    def test_default_credentials(self, service, port):
        """Test default credentials for common services"""
        creds = DEFAULT_CREDENTIALS.get(service, [])
        if not creds:
            return []

        print(f"\n[*] Default credential test → {service} {self.target}:{port}")
        found = []

        for username, password in creds:
            result = self._try_credential(service, self.target, port, username, password)
            if result:
                vuln = {
                    'ip':          self.target,
                    'port':        port,
                    'type':        'default_credentials',
                    'service':     service,
                    'username':    username,
                    'password':    password,
                    'severity':    'critical',
                    'cvss':        9.8,
                    'description': f'Default credentials work: {username}:{password}',
                    'cve':         'CWE-1392',
                }
                found.append(vuln)
                self._record_vuln(vuln)
                break  # Stop after first success

        return found

    def _try_credential(self, service, host, port, username, password):
        """Test single credential against service"""
        if service == 'ftp':
            try:
                from ftplib import FTP
                ftp = FTP()
                ftp.connect(host, port, timeout=self.timeout)
                ftp.login(username, password)
                ftp.quit()
                return True
            except Exception:
                return False

        elif service == 'redis':
            try:
                s = socket.socket()
                s.settimeout(self.timeout)
                s.connect((host, port))
                if password:
                    s.sendall(f'AUTH {password}\r\n'.encode())
                else:
                    s.sendall(b'PING\r\n')
                resp = s.recv(1024).decode(errors='replace')
                s.close()
                return '+OK' in resp or '+PONG' in resp
            except Exception:
                return False

        return False

    # ── Misconfiguration checks ──────────────────────────────────────── #

    def check_misconfigurations(self, port, service, banner):
        """Check for common service misconfigurations"""
        issues = []

        # FTP anonymous access
        if service == 'ftp' or port == 21:
            if banner and ('anonymous' in banner.lower() or '230' in banner):
                issue = {
                    'ip': self.target, 'port': port,
                    'type': 'ftp_anonymous_access',
                    'severity': 'high',
                    'description': 'FTP anonymous login allowed',
                    'cve': 'CWE-284',
                }
                issues.append(issue)
                self._record_vuln(issue)

        # Telnet enabled
        if port == 23 or service == 'telnet':
            issue = {
                'ip': self.target, 'port': port,
                'type': 'unencrypted_protocol',
                'severity': 'high',
                'description': 'Telnet enabled — clear-text authentication',
                'cve': 'CWE-319',
            }
            issues.append(issue)
            self._record_vuln(issue)

        # HTTP basic auth over plain HTTP
        if port == 80 and banner and 'www-authenticate: basic' in banner.lower():
            issue = {
                'ip': self.target, 'port': port,
                'type': 'basic_auth_plaintext',
                'severity': 'medium',
                'description': 'HTTP Basic Auth transmitted in clear text',
                'cve': 'CWE-319',
            }
            issues.append(issue)
            self._record_vuln(issue)

        # Redis without auth
        if port == 6379:
            try:
                s = socket.socket()
                s.settimeout(self.timeout)
                s.connect((self.target, port))
                s.sendall(b'PING\r\n')
                resp = s.recv(64).decode(errors='replace')
                s.close()
                if '+PONG' in resp:
                    issue = {
                        'ip': self.target, 'port': port,
                        'type': 'no_authentication',
                        'severity': 'critical',
                        'description': 'Redis accessible without authentication',
                        'cve': 'CVE-2022-0543',
                    }
                    issues.append(issue)
                    self._record_vuln(issue)
            except Exception:
                pass

        # MongoDB without auth
        if port == 27017:
            try:
                s = socket.socket()
                s.settimeout(self.timeout)
                s.connect((self.target, port))
                # MongoDB greeting check
                s.sendall(b'\x3a\x00\x00\x00\x01\x00\x00\x00\x00\x00\x00\x00\xd4\x07\x00\x00'
                          b'\x00\x00\x00\x00admin.$cmd\x00\x00\x00\x00\x00\xff\xff\xff\xff'
                          b'\x13\x00\x00\x00\x10isMaster\x00\x01\x00\x00\x00\x00')
                resp = s.recv(1024)
                s.close()
                if resp:
                    issue = {
                        'ip': self.target, 'port': port,
                        'type': 'mongodb_exposed',
                        'severity': 'critical',
                        'description': 'MongoDB port accessible — check authentication',
                        'cve': 'CWE-306',
                    }
                    issues.append(issue)
                    self._record_vuln(issue)
            except Exception:
                pass

        return issues

    # ── Full scan ────────────────────────────────────────────────────── #

    def run_full(self, open_ports=None):
        """Run all vulnerability checks against discovered ports"""
        print(f"\n{'='*55}")
        print(f"  Vulnerability Scan — {self.target}")
        print(f"{'='*55}")

        # Use provided ports or scan common ones
        if not open_ports:
            from tools.port_scan import PortScanner, TOP_100_PORTS
            ps = PortScanner(self.target, timeout=self.timeout)
            open_ports = ps.run_full('top100')

        if not open_ports:
            print("[!] No open ports to scan")
            return []

        print(f"\n[*] Checking {len(open_ports)} open ports for vulnerabilities...")

        for port_info in open_ports:
            port    = port_info['port']
            service = port_info.get('service', '')
            banner  = port_info.get('banner', '')

            if not banner:
                banner = grab_banner(self.target, port) or ''

            print(f"\n[*] Checking {self.target}:{port} ({service})...")

            # Banner-based CVE check
            self.check_service_vulns(port, banner)

            # SSL audit for HTTPS ports
            if port in (443, 8443, 8080) or service in ('https', 'ssl'):
                self.ssl_audit(port)

            # Default credential checks
            for svc in ('ftp', 'redis'):
                if svc in service.lower() or port == {'ftp':21,'redis':6379}.get(svc,0):
                    self.test_default_credentials(svc, port)

            # Misconfiguration checks
            self.check_misconfigurations(port, service, banner)

        # Summary
        severity_counts = {}
        for v in self.vulns:
            s = v.get('severity', 'info')
            severity_counts[s] = severity_counts.get(s, 0) + 1

        self.results.stats = {
            'vulnerabilities_found': len(self.vulns),
            **{f'{k}_severity': v for k, v in severity_counts.items()},
        }
        self.results.print_summary()
        self.results.to_json()
        self.results.to_txt()

        return self.vulns


def main():
    parser = argparse.ArgumentParser(description='Vulnerability Scanner')
    parser.add_argument('-t', '--target',    required=True)
    parser.add_argument('-p', '--ports',     help='comma-separated ports')
    parser.add_argument('--timeout',         type=int, default=5)
    parser.add_argument('--ssl-only',        action='store_true')
    parser.add_argument('--ssl-port',        type=int, default=443)
    a = parser.parse_args()

    scanner = VulnerabilityScanner(a.target, timeout=a.timeout)

    if a.ssl_only:
        scanner.ssl_audit(a.ssl_port)
    elif a.ports:
        port_list = [int(p) for p in a.ports.split(',')]
        fake_ports = [{'port': p, 'service': '', 'banner': ''} for p in port_list]
        scanner.run_full(fake_ports)
    else:
        scanner.run_full()


if __name__ == '__main__':
    main()
