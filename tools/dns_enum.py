#!/usr/bin/env python3
"""
DNS Enumeration Tool
Zone transfers, subdomain brute-force, record enumeration, cache snooping
"""

import sys, os, argparse, threading, queue, socket, time, random
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))
from utils.recon_utils import ScanResults, Progress

try:
    import dns.resolver, dns.query, dns.zone, dns.rdatatype, dns.exception
    DNS_LIB = True
except ImportError:
    DNS_LIB = False
    print("[!] dnspython not installed: pip3 install dnspython")


RECORD_TYPES = ['A', 'AAAA', 'MX', 'NS', 'TXT', 'CNAME', 'SOA',
                'SRV', 'PTR', 'CAA', 'DMARC', 'SPF']

DEFAULT_SUBDOMAINS = [
    'www', 'mail', 'smtp', 'pop', 'imap', 'ftp', 'webmail', 'vpn', 'remote',
    'dev', 'staging', 'test', 'demo', 'api', 'admin', 'portal', 'dashboard',
    'app', 'mobile', 'shop', 'store', 'blog', 'wiki', 'docs', 'support',
    'help', 'status', 'monitoring', 'cdn', 'static', 'assets', 'img',
    'ns1', 'ns2', 'ns3', 'mx1', 'mx2', 'mx3',
    'backup', 'old', 'new', 'legacy', 'internal', 'intranet', 'extranet',
    'git', 'svn', 'jira', 'confluence', 'jenkins', 'ci', 'docker',
    'db', 'database', 'mysql', 'sql', 'redis', 'mongo', 'elastic',
    'ldap', 'ad', 'dc', 'dc1', 'dc2', 'sso', 'auth',
    'download', 'upload', 'files', 'media', 'images',
    'mx', 'smtp2', 'mail2', 'email', 'webmail2',
    'crm', 'erp', 'hr', 'finance', 'accounting',
    'fw', 'firewall', 'proxy', 'gateway', 'edge',
]


class DNSEnumerator:

    def __init__(self, domain, threads=10, timeout=3, wordlist=None):
        self.domain   = domain
        self.threads  = threads
        self.timeout  = timeout
        self.wordlist = wordlist
        self.results  = ScanResults('dns_enumeration', domain)
        self.lock     = threading.Lock()

        if DNS_LIB:
            self.resolver = dns.resolver.Resolver()
            self.resolver.timeout     = timeout
            self.resolver.lifetime    = timeout
            self.resolver.nameservers = ['8.8.8.8', '1.1.1.1', '8.8.4.4']

    # ------------------------------------------------------------------ #

    def get_nameservers(self):
        """Get authoritative name servers for domain"""
        nameservers = []
        if not DNS_LIB:
            return nameservers

        try:
            ans = self.resolver.resolve(self.domain, 'NS')
            for rdata in ans:
                ns = str(rdata.target).rstrip('.')
                ip = self._resolve(ns)
                nameservers.append({'ns': ns, 'ip': ip})
                print(f"  [NS] {ns}  ({ip})")
        except Exception as e:
            print(f"  [!] NS lookup failed: {e}")

        return nameservers

    def _resolve(self, host, rtype='A'):
        try:
            ans = self.resolver.resolve(host, rtype)
            return str(ans[0])
        except Exception:
            return None

    def zone_transfer(self, nameserver=None):
        """
        Attempt DNS zone transfer (AXFR)
        Returns all records if server is misconfigured
        """
        if not DNS_LIB:
            return []

        records = []
        ns_list = []

        if nameserver:
            ns_list = [nameserver]
        else:
            try:
                ns_ans = self.resolver.resolve(self.domain, 'NS')
                for rdata in ns_ans:
                    ns_host = str(rdata.target).rstrip('.')
                    ns_ip   = self._resolve(ns_host)
                    if ns_ip:
                        ns_list.append(ns_ip)
            except Exception:
                pass

        for ns_ip in ns_list:
            print(f"\n  [*] Attempting zone transfer from {ns_ip}...")
            try:
                zone = dns.zone.from_xfr(dns.query.xfr(ns_ip, self.domain,
                                                         timeout=self.timeout))
                print(f"  [!] ZONE TRANSFER SUCCESSFUL from {ns_ip}!")
                for name, node in zone.nodes.items():
                    rdatasets = node.rdatasets
                    for rdataset in rdatasets:
                        for rdata in rdataset:
                            record = {
                                'type':   dns.rdatatype.to_text(rdataset.rdtype),
                                'name':   f"{name}.{self.domain}",
                                'value':  str(rdata),
                                'source': 'zone_transfer',
                            }
                            records.append(record)
                            self.results.add(record)
                            print(f"  [AXFR] {record['name']} {record['type']} {record['value']}")
            except Exception:
                print(f"  [-] Zone transfer refused by {ns_ip}")

        return records

    def enumerate_records(self):
        """Query all standard DNS record types"""
        print(f"\n  [*] Enumerating DNS records for {self.domain}...")
        found = []

        for rtype in RECORD_TYPES:
            try:
                ans = self.resolver.resolve(self.domain, rtype)
                for rdata in ans:
                    record = {
                        'type':  rtype,
                        'name':  self.domain,
                        'value': str(rdata),
                    }
                    found.append(record)
                    self.results.add(record)
                    print(f"  [{rtype:6s}] {str(rdata)}")
            except dns.resolver.NoAnswer:
                pass
            except dns.resolver.NXDOMAIN:
                break
            except Exception:
                pass

        return found

    def subdomain_bruteforce(self, wordlist=None):
        """Multi-threaded subdomain enumeration"""
        subdomains = []

        if wordlist:
            try:
                with open(wordlist) as f:
                    subdomains = [l.strip() for l in f if l.strip() and not l.startswith('#')]
            except FileNotFoundError:
                print(f"  [!] Wordlist not found: {wordlist}, using built-in list")

        if not subdomains:
            subdomains = DEFAULT_SUBDOMAINS

        print(f"\n  [*] Brute-forcing {len(subdomains)} subdomains "
              f"({self.threads} threads)...")

        q       = queue.Queue()
        found   = []
        prog    = Progress(len(subdomains), 'Subdomains')

        for sub in subdomains:
            q.put(sub)

        def worker():
            while True:
                try:
                    sub = q.get(timeout=1)
                except queue.Empty:
                    break

                fqdn = f"{sub}.{self.domain}"
                try:
                    ip = self._resolve(fqdn)
                    if ip:
                        record = {
                            'type':      'A',
                            'subdomain': fqdn,
                            'ip':        ip,
                            'source':    'bruteforce',
                        }
                        with self.lock:
                            found.append(record)
                            self.results.add(record)
                            print(f"\n  [+] {fqdn:<45} {ip}")
                except Exception:
                    pass
                finally:
                    prog.update()
                    q.task_done()

        threads = [threading.Thread(target=worker, daemon=True)
                   for _ in range(self.threads)]
        for t in threads:
            t.start()
        q.join()
        prog.done()

        return found

    def reverse_lookup_range(self, cidr):
        """Reverse DNS lookups for entire CIDR range"""
        from utils.recon_utils import expand_cidr
        hosts = expand_cidr(cidr)

        print(f"\n  [*] Reverse DNS for {len(hosts)} IPs in {cidr}...")

        found = []
        prog  = Progress(len(hosts), 'Reverse DNS')

        for ip in hosts:
            try:
                hostname = socket.gethostbyaddr(ip)[0]
                record = {'ip': ip, 'hostname': hostname, 'type': 'PTR'}
                found.append(record)
                self.results.add(record)
                print(f"\n  [PTR] {ip:<18} → {hostname}")
            except Exception:
                pass
            prog.update()

        prog.done()
        return found

    def wildcard_check(self):
        """Detect wildcard DNS (would cause false positives in brute-force)"""
        random_sub = f"{''.join(random.choices('abcdefghijklmnop', k=12))}.{self.domain}"
        ip = self._resolve(random_sub)
        if ip:
            print(f"  [!] Wildcard DNS detected → {random_sub} resolves to {ip}")
            print(f"  [!] Subdomain brute-force results may include false positives")
            return True
        return False

    def cache_snoop(self, nameserver, domains):
        """
        DNS Cache Snooping — check if server has cached specific domains.
        Uses non-recursive query; cached record → server recently resolved it.
        """
        print(f"\n  [*] Cache snooping {nameserver} for {len(domains)} domains...")
        cached = []

        resolver = dns.resolver.Resolver()
        resolver.nameservers = [nameserver]
        resolver.timeout     = self.timeout

        for domain in domains:
            try:
                # Non-recursive query (RD=0) — only answers from cache
                request = dns.message.make_query(domain, 'A')
                request.flags &= ~dns.flags.RD  # Clear recursion desired
                response = dns.query.udp(request, nameserver, timeout=self.timeout)

                if response.answer:
                    result = {'domain': domain, 'cached': True,
                              'nameserver': nameserver}
                    cached.append(result)
                    self.results.add(result)
                    print(f"  [CACHED] {domain}")
            except Exception:
                pass

        return cached

    def run_full(self, subdomain_wordlist=None):
        """Run complete DNS enumeration suite"""
        print(f"\n{'='*55}")
        print(f"  DNS Enumeration — {self.domain}")
        print(f"{'='*55}")

        if not DNS_LIB:
            print("[!] Install dnspython: pip3 install dnspython")
            return

        # 1. Get nameservers
        print("\n[*] Step 1/5 — Nameserver discovery")
        ns_list = self.get_nameservers()

        # 2. Zone transfer attempts
        print("\n[*] Step 2/5 — Zone transfer attempts")
        self.zone_transfer()

        # 3. Enumerate all record types
        print("\n[*] Step 3/5 — DNS record enumeration")
        self.enumerate_records()

        # 4. Wildcard check + subdomain brute-force
        print("\n[*] Step 4/5 — Subdomain brute-force")
        self.wildcard_check()
        self.subdomain_bruteforce(subdomain_wordlist)

        # 5. Summary
        print("\n[*] Step 5/5 — Saving results")
        self.results.stats = {
            'nameservers': len(ns_list),
            'total_found': self.results.get_count(),
        }
        self.results.print_summary()
        self.results.to_json()
        self.results.to_txt()


# ------------------------------------------------------------------ #

def main():
    parser = argparse.ArgumentParser(description='DNS Enumeration Tool')
    parser.add_argument('-d', '--domain',    required=True, help='Target domain')
    parser.add_argument('-w', '--wordlist',  help='Subdomain wordlist')
    parser.add_argument('-t', '--threads',   type=int, default=10)
    parser.add_argument('--timeout',         type=int, default=3)
    parser.add_argument('--zone-transfer',   action='store_true')
    parser.add_argument('--records-only',    action='store_true')
    parser.add_argument('--subdomains-only', action='store_true')
    parser.add_argument('--reverse-cidr',    help='CIDR for reverse DNS sweep')
    a = parser.parse_args()

    enumerator = DNSEnumerator(a.domain, a.threads, a.timeout, a.wordlist)

    if a.zone_transfer:
        enumerator.zone_transfer()
    elif a.records_only:
        enumerator.enumerate_records()
    elif a.subdomains_only:
        enumerator.subdomain_bruteforce(a.wordlist)
    elif a.reverse_cidr:
        enumerator.reverse_lookup_range(a.reverse_cidr)
    else:
        enumerator.run_full(a.wordlist)


if __name__ == '__main__':
    main()
