#!/usr/bin/env python3
"""
Ping Sweep Tool
Fast multi-threaded ICMP + TCP ping sweep across network ranges
"""

import sys, os, argparse, threading, queue, socket, time, subprocess, platform
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))
from utils.recon_utils import ScanResults, Progress, expand_cidr, reverse_dns, guess_os_from_ttl

try:
    from scapy.all import IP, ICMP, sr1, conf
    conf.verb = 0
    SCAPY = True
except ImportError:
    SCAPY = False


class PingSweep:

    def __init__(self, target, threads=100, timeout=1.0, randomize=False):
        self.target    = target
        self.threads   = threads
        self.timeout   = timeout
        self.randomize = randomize
        self.results   = ScanResults('ping_sweep', target)
        self.lock      = threading.Lock()
        self.live      = []

    # ── Core ping methods ────────────────────────────────────────────── #

    def _scapy_ping(self, ip):
        """ICMP echo via Scapy — returns (alive, ttl)"""
        try:
            pkt  = IP(dst=ip, ttl=64) / ICMP(id=os.getpid() & 0xFFFF)
            resp = sr1(pkt, timeout=self.timeout, verbose=0)
            if resp and ICMP in resp and resp[ICMP].type == 0:
                return True, resp[IP].ttl
        except Exception:
            pass
        return False, 0

    def _sys_ping(self, ip):
        """ICMP via system ping — no root required"""
        flag    = '-n' if platform.system().lower() == 'windows' else '-c'
        timeout = '-w' if platform.system().lower() == 'windows' else '-W'
        cmd = ['ping', flag, '1', timeout, '1', ip]
        try:
            ret = subprocess.run(cmd, capture_output=True, timeout=3).returncode
            return ret == 0, 0
        except Exception:
            return False, 0

    def _tcp_ping(self, ip, port=80):
        """TCP connect to determine liveness — no ICMP required"""
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.settimeout(self.timeout)
            r = s.connect_ex((ip, port))
            s.close()
            return r in (0, 111)  # 0=open, 111=refused (host is alive)
        except Exception:
            return False

    # ── Sweep methods ────────────────────────────────────────────────── #

    def sweep(self, hosts):
        """
        Main sweep — tries Scapy ICMP first, falls back to system ping,
        then TCP on common ports.
        """
        import random as rnd

        if self.randomize:
            hosts = hosts[:]
            rnd.shuffle(hosts)

        total = len(hosts)
        print(f"\n[*] Sweeping {total} hosts  "
              f"(threads={self.threads}, timeout={self.timeout}s"
              f"{', randomized' if self.randomize else ''})")

        q    = queue.Queue()
        prog = Progress(total, 'Sweep')

        for h in hosts:
            q.put(h)

        def worker():
            while True:
                try:
                    ip = q.get(timeout=1)
                except queue.Empty:
                    break

                try:
                    alive, ttl = False, 0

                    if SCAPY and platform.system() != 'Windows' and os.geteuid() == 0:
                        alive, ttl = self._scapy_ping(ip)

                    if not alive:
                        alive, _ = self._sys_ping(ip)

                    if not alive:
                        # Try TCP on 80, 443, 22
                        for port in [80, 443, 22, 8080]:
                            if self._tcp_ping(ip, port):
                                alive = True
                                break

                    if alive:
                        self._record(ip, ttl)
                finally:
                    prog.update()
                    q.task_done()

        threads = [threading.Thread(target=worker, daemon=True)
                   for _ in range(min(self.threads, total))]
        for t in threads:
            t.start()
        q.join()
        prog.done()

    def _record(self, ip, ttl):
        with self.lock:
            if any(h['ip'] == ip for h in self.live):
                return

            hostname = reverse_dns(ip)
            os_hint  = guess_os_from_ttl(ttl) if ttl > 0 else ''

            host = {
                'ip':       ip,
                'ttl':      ttl,
                'hostname': hostname or '',
                'os_hint':  os_hint,
                'alive':    True,
            }
            self.live.append(host)
            self.results.add(host)

            h_str  = f"  ({hostname})" if hostname else ''
            os_str = f"  [{os_hint}]"  if os_hint  else ''
            ttl_s  = f"  TTL:{ttl}"    if ttl > 0   else ''
            print(f"\n  [UP] {ip:<18}{ttl_s}{h_str}{os_str}")

    # ── Entry point ──────────────────────────────────────────────────── #

    def run(self):
        print(f"\n{'='*55}")
        print(f"  Ping Sweep — {self.target}")
        print(f"{'='*55}")

        # Resolve target to host list
        if '/' in self.target:
            hosts = expand_cidr(self.target)
        elif '-' in self.target.split('.')[-1]:
            base  = '.'.join(self.target.split('.')[:3])
            rng   = self.target.split('.')[-1].split('-')
            hosts = [f"{base}.{i}" for i in range(int(rng[0]), int(rng[1])+1)]
        else:
            hosts = [self.target]

        self.sweep(hosts)

        # Summary
        up_count = len(self.live)
        print(f"\n  Result: {up_count}/{len(hosts)} hosts alive\n")

        if self.live:
            print("  Live hosts:")
            for h in sorted(self.live, key=lambda x: socket.inet_aton(x['ip'])):
                h_str  = f"  ({h['hostname']})"  if h['hostname'] else ''
                os_str = f"  [{h['os_hint']}]"   if h['os_hint']  else ''
                print(f"    {h['ip']:<18}{h_str}{os_str}")

        self.results.stats = {
            'total_hosts':  len(hosts),
            'alive':        up_count,
            'down':         len(hosts) - up_count,
        }
        self.results.print_summary()
        self.results.to_json()
        self.results.to_txt()

        return self.live


def main():
    parser = argparse.ArgumentParser(description='Ping Sweep Tool')
    parser.add_argument('-t', '--target',   required=True,
                        help='IP, CIDR (10.0.0.0/24) or range (10.0.0.1-254)')
    parser.add_argument('--threads',        type=int,   default=100)
    parser.add_argument('--timeout',        type=float, default=1.0)
    parser.add_argument('--randomize',      action='store_true',
                        help='Randomize scan order (evasion)')
    a = parser.parse_args()

    sweep = PingSweep(a.target, a.threads, a.timeout, a.randomize)
    sweep.run()


if __name__ == '__main__':
    main()
