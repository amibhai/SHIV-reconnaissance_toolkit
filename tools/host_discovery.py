#!/usr/bin/env python3
"""
Host Discovery Tool
ARP sweep, ICMP ping, TCP/UDP probing — multi-method live host detection
"""

import sys, os, argparse, threading, queue, socket, struct, time, random
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))
from utils.recon_utils import ScanResults, Progress, expand_cidr, reverse_dns, is_valid_ip

try:
    from scapy.all import ARP, Ether, IP, ICMP, TCP, UDP, srp, sr1, conf
    conf.verb = 0
    SCAPY = True
except ImportError:
    SCAPY = False


class HostDiscovery:

    def __init__(self, target, threads=50, timeout=1.0):
        self.target  = target
        self.threads = threads
        self.timeout = timeout
        self.results = ScanResults('host_discovery', target)
        self.lock    = threading.Lock()
        self.live    = []

    # ──────────────────────────── ARP ────────────────────────────────── #

    def arp_sweep(self, network):
        """
        ARP sweep — most reliable for local /16 or smaller networks.
        Cannot cross routers.  Reveals MAC address + vendor.
        """
        if not SCAPY:
            print("[!] ARP sweep requires Scapy")
            return []

        hosts = expand_cidr(network)
        print(f"\n[*] ARP sweep → {network} ({len(hosts)} hosts)")

        pkt  = Ether(dst="ff:ff:ff:ff:ff:ff") / ARP(pdst=network)
        ans, _ = srp(pkt, timeout=self.timeout, verbose=0)

        found = []
        for sent, rcvd in ans:
            ip  = rcvd.psrc
            mac = rcvd.hwsrc
            vendor = self._mac_vendor(mac)
            host = {
                'ip': ip, 'mac': mac, 'vendor': vendor,
                'method': 'ARP', 'hostname': reverse_dns(ip)
            }
            found.append(host)
            self.results.add(host)
            print(f"  [ARP]  {ip:<18}  {mac}  {vendor}")

        return found

    def _mac_vendor(self, mac):
        """Lookup vendor from MAC OUI prefix"""
        oui_map = {
            '00:50:56': 'VMware', '00:0c:29': 'VMware', '00:1c:42': 'Parallels',
            '52:54:00': 'QEMU/KVM', '08:00:27': 'VirtualBox',
            'dc:a6:32': 'Raspberry Pi', 'b8:27:eb': 'Raspberry Pi',
            'fc:ec:da': 'Ubiquiti', '00:15:5d': 'Hyper-V',
            '00:50:ba': 'D-Link', '00:1a:4b': 'Cisco',
        }
        prefix = mac[:8].lower()
        return oui_map.get(prefix, 'Unknown')

    # ──────────────────────────── ICMP ───────────────────────────────── #

    def icmp_sweep(self, hosts):
        """Multi-threaded ICMP echo sweep"""
        print(f"\n[*] ICMP sweep → {len(hosts)} hosts ({self.threads} threads)")

        q    = queue.Queue()
        prog = Progress(len(hosts), 'ICMP')

        for h in hosts:
            q.put(h)

        def worker():
            while True:
                try:
                    ip = q.get(timeout=1)
                except queue.Empty:
                    break
                try:
                    if SCAPY:
                        self._scapy_icmp(ip)
                    else:
                        self._socket_ping(ip)
                finally:
                    prog.update()
                    q.task_done()

        threads = [threading.Thread(target=worker, daemon=True)
                   for _ in range(self.threads)]
        for t in threads:
            t.start()
        q.join()
        prog.done()

    def _scapy_icmp(self, ip):
        pkt  = IP(dst=ip) / ICMP()
        resp = sr1(pkt, timeout=self.timeout, verbose=0)
        if resp and ICMP in resp:
            ttl = resp[IP].ttl
            self._record_host(ip, 'ICMP', ttl)

    def _socket_ping(self, ip):
        """Fallback ICMP via subprocess ping"""
        import subprocess, platform
        is_windows = platform.system().lower() == 'windows'
        flag  = '-n' if is_windows else '-c'
        wait  = ['-w', '1000'] if is_windows else ['-W', '1']
        cmd   = ['ping', flag, '1', *wait, ip]
        ret   = subprocess.run(cmd, capture_output=True).returncode
        if ret == 0:
            self._record_host(ip, 'ICMP-ping', 0)

    # ──────────────────────────── TCP ────────────────────────────────── #

    def tcp_sweep(self, hosts, ports=None):
        """
        TCP-based host discovery.
        Probes common ports — any response (SYN-ACK or RST) = alive.
        """
        if ports is None:
            ports = [22, 80, 443, 445, 3389, 8080, 8443]

        print(f"\n[*] TCP sweep → {len(hosts)} hosts, ports {ports}")

        q    = queue.Queue()
        prog = Progress(len(hosts), 'TCP')

        for h in hosts:
            q.put(h)

        def worker():
            while True:
                try:
                    ip = q.get(timeout=1)
                except queue.Empty:
                    break
                for port in ports:
                    if self._tcp_probe(ip, port):
                        self._record_host(ip, f'TCP:{port}', 0)
                        break
                prog.update()
                q.task_done()

        threads = [threading.Thread(target=worker, daemon=True)
                   for _ in range(self.threads)]
        for t in threads:
            t.start()
        q.join()
        prog.done()

    def _tcp_probe(self, ip, port):
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.settimeout(self.timeout)
            result = s.connect_ex((ip, port))
            s.close()
            return result in (0, 111)  # 0=open, 111=refused (host alive)
        except Exception:
            return False

    # ──────────────────────────── UDP ────────────────────────────────── #

    def udp_sweep(self, hosts):
        """UDP probes to common services for host discovery"""
        udp_probes = {
            53:  b'\xaa\xbb\x01\x00\x00\x01\x00\x00\x00\x00\x00\x00'
                 b'\x07example\x03com\x00\x00\x01\x00\x01',  # DNS
            123: b'\x1b' + b'\x00' * 47,   # NTP
            161: b'\x30\x26\x02\x01\x01\x04\x06public\xa0\x19'
                 b'\x02\x04\x00\x00\x00\x01\x02\x01\x00\x02\x01\x00'
                 b'\x30\x0b\x30\x09\x06\x05+\x06\x01\x02\x01\x05\x00',  # SNMP
        }

        print(f"\n[*] UDP discovery → {len(hosts)} hosts")

        def probe_host(ip):
            for port, payload in udp_probes.items():
                try:
                    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
                    s.settimeout(self.timeout)
                    s.sendto(payload, (ip, port))
                    data, _ = s.recvfrom(1024)
                    if data:
                        self._record_host(ip, f'UDP:{port}', 0)
                        return
                except socket.timeout:
                    pass
                except Exception:
                    pass
                finally:
                    try:
                        s.close()
                    except Exception:
                        pass

        threads = [threading.Thread(target=probe_host, args=(ip,), daemon=True)
                   for ip in hosts]
        for t in threads:
            t.start()
        for t in threads:
            t.join()

    # ──────────────────────────── shared ─────────────────────────────── #

    def _record_host(self, ip, method, ttl):
        with self.lock:
            # Avoid duplicates
            if any(h['ip'] == ip for h in self.live):
                return

            hostname = reverse_dns(ip)
            from utils.recon_utils import guess_os_from_ttl
            os_guess = guess_os_from_ttl(ttl) if ttl > 0 else ''

            host = {
                'ip':       ip,
                'method':   method,
                'ttl':      ttl,
                'hostname': hostname or '',
                'os_hint':  os_guess,
            }
            self.live.append(host)
            self.results.add(host)

            hostname_str = f"({hostname})" if hostname else ''
            os_str       = f"  [{os_guess}]" if os_guess else ''
            print(f"\n  [LIVE] {ip:<18} {hostname_str:<30} {method}{os_str}")

    # ──────────────────────────── full run ───────────────────────────── #

    def run_full(self):
        """Run all discovery methods against the target"""
        print(f"\n{'='*55}")
        print(f"  Host Discovery — {self.target}")
        print(f"{'='*55}")

        # Determine target type
        if '/' in self.target:
            hosts = expand_cidr(self.target)
        elif '-' in self.target.split('.')[-1]:
            # e.g. 192.168.1.1-254
            base   = '.'.join(self.target.split('.')[:3])
            r      = self.target.split('.')[-1].split('-')
            hosts  = [f"{base}.{i}" for i in range(int(r[0]), int(r[1])+1)]
        elif is_valid_ip(self.target):
            hosts  = [self.target]
        else:
            ip = socket.gethostbyname(self.target)
            hosts = [ip]

        print(f"\n[*] Target range: {len(hosts)} potential hosts")

        # ARP sweep (local network only)
        if '/' in self.target:
            try:
                self.arp_sweep(self.target)
            except Exception as e:
                print(f"  [!] ARP sweep failed: {e}")

        # ICMP sweep
        self.icmp_sweep(hosts)

        # TCP sweep for hosts not found yet
        found_ips    = {h['ip'] for h in self.live}
        remaining    = [h for h in hosts if h not in found_ips]
        if remaining:
            self.tcp_sweep(remaining)

        # Summary
        self.results.stats = {
            'total_scanned': len(hosts),
            'live_hosts':    len(self.live),
        }
        self.results.print_summary()
        self.results.to_json()
        self.results.to_txt()

        return self.live


def main():
    parser = argparse.ArgumentParser(description='Host Discovery Tool')
    parser.add_argument('-t', '--target',  required=True,
                        help='IP, CIDR (192.168.1.0/24) or range (192.168.1.1-254)')
    parser.add_argument('--threads',       type=int, default=50)
    parser.add_argument('--timeout',       type=float, default=1.0)
    parser.add_argument('--arp',           action='store_true', help='ARP only')
    parser.add_argument('--icmp',          action='store_true', help='ICMP only')
    parser.add_argument('--tcp',           action='store_true', help='TCP only')
    a = parser.parse_args()

    disc = HostDiscovery(a.target, a.threads, a.timeout)

    if a.arp:
        disc.arp_sweep(a.target)
    elif a.icmp:
        hosts = expand_cidr(a.target) if '/' in a.target else [a.target]
        disc.icmp_sweep(hosts)
    elif a.tcp:
        hosts = expand_cidr(a.target) if '/' in a.target else [a.target]
        disc.tcp_sweep(hosts)
    else:
        disc.run_full()


if __name__ == '__main__':
    main()
