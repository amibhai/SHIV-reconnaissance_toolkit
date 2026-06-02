"""
recon.modules.dns_enum — Production-grade DNS enumeration module.

Features:
- Zone transfer (AXFR) against all nameservers
- Wildcard detection with 3-probe pre-check
- Multi-threaded subdomain brute-force with custom resolver pool
- DNS-over-HTTPS fallback (Cloudflare / Google)
- DNS cache snooping
- DNSSEC validation (DS, DNSKEY, RRSIG)
- Reverse DNS sweep over CIDR
- Realistic evasion rate limiting
"""

from __future__ import annotations

import ipaddress
import json
import os
import random
import socket
import string
import threading
import time
import urllib.request
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import dns.exception
import dns.flags
import dns.message
import dns.name
import dns.query
import dns.rdatatype
import dns.resolver
import dns.reversename
import dns.zone

from recon.core.config import ReconConfig
from recon.core.logger import get_logger, make_progress

__all__ = ["DNSEnumerator", "DNSRecord"]

_log = get_logger("dns_enum")

_RECORD_TYPES = [
    "A", "AAAA", "MX", "NS", "TXT", "CNAME", "SOA",
    "SRV", "CAA", "PTR", "HINFO", "NAPTR", "DNSKEY", "DS", "RRSIG",
]

_HIGH_VALUE_TARGETS = [
    "gmail.com", "facebook.com", "paypal.com", "amazon.com",
    "bankofamerica.com", "wellsfargo.com", "chase.com",
    "microsoft.com", "apple.com", "google.com",
]

_DOH_ENDPOINTS = [
    "https://cloudflare-dns.com/dns-query",
    "https://dns.google/dns-query",
]


@dataclass
class DNSRecord:
    """A single DNS record result."""
    name: str
    record_type: str
    value: str
    ttl: int = 0
    source: str = "direct"
    dnssec: bool = False


class DNSEnumerator:
    """
    Comprehensive DNS enumeration engine.

    Args:
        domain: Target domain to enumerate.
        config: ReconConfig instance.
        wordlist_path: Path to subdomain wordlist (overrides config default).
    """

    def __init__(
        self,
        domain: str,
        config: ReconConfig | None = None,
        wordlist_path: Path | None = None,
    ) -> None:
        self.domain = domain.rstrip(".")
        self.config = config or ReconConfig()
        self._wordlist_path = wordlist_path
        self._results: list[DNSRecord] = []
        self._lock = threading.Lock()
        self._resolver_pool: list[str] = []
        self._wildcard_ips: set[str] = set()
        self._is_wildcard = False
        self._setup_resolvers()

    # ------------------------------------------------------------------ #
    # Setup                                                                #
    # ------------------------------------------------------------------ #

    def _setup_resolvers(self) -> None:
        """Load custom resolver pool from file, fall back to system resolvers."""
        path = self.config.dns_resolvers_file
        if path.exists():
            lines = path.read_text(encoding="utf-8").splitlines()
            self._resolver_pool = [l.strip() for l in lines if l.strip() and not l.startswith("#")]
        if not self._resolver_pool:
            self._resolver_pool = ["8.8.8.8", "8.8.4.4", "1.1.1.1", "9.9.9.9"]
        _log.debug("Loaded %d resolvers", len(self._resolver_pool))

    def _make_resolver(self) -> dns.resolver.Resolver:
        """Build a dns.resolver.Resolver with a random resolver from the pool."""
        r = dns.resolver.Resolver(configure=False)
        r.nameservers = [random.choice(self._resolver_pool)]
        r.timeout = self.config.timeout
        r.lifetime = self.config.timeout * 2
        return r

    def _evasion_sleep(self) -> None:
        if self.config.evasion_level >= 2:
            time.sleep(random.uniform(0.05, 0.4))
        elif self.config.evasion_level >= 1:
            time.sleep(random.uniform(0.0, 0.05))

    def _add_record(self, record: DNSRecord) -> None:
        with self._lock:
            self._results.append(record)

    # ------------------------------------------------------------------ #
    # Nameserver discovery                                                 #
    # ------------------------------------------------------------------ #

    def get_nameservers(self) -> list[str]:
        """
        Resolve NS records for the domain.

        Returns:
            List of nameserver hostnames.
        """
        ns_list: list[str] = []
        try:
            resolver = self._make_resolver()
            answers = resolver.resolve(self.domain, "NS")
            for rdata in answers:
                ns = str(rdata.target).rstrip(".")
                ns_list.append(ns)
                _log.debug("NS: %s", ns)
        except Exception as exc:
            _log.warning("NS lookup failed for %s: %s", self.domain, exc)
        return ns_list

    # ------------------------------------------------------------------ #
    # Zone transfer                                                        #
    # ------------------------------------------------------------------ #

    def zone_transfer(self) -> list[DNSRecord]:
        """
        Attempt AXFR zone transfer against all known nameservers.

        Returns:
            List of DNSRecord objects from successful transfers.
        """
        records: list[DNSRecord] = []
        nameservers = self.get_nameservers()
        if not nameservers:
            _log.warning("No nameservers found; skipping zone transfer")
            return records

        for ns in nameservers:
            try:
                ns_ip = socket.gethostbyname(ns)
                _log.info("Attempting AXFR against %s (%s)", ns, ns_ip)
                zone = dns.zone.from_xfr(dns.query.xfr(ns_ip, self.domain, timeout=self.config.timeout))
                for name, node in zone.nodes.items():
                    for rdataset in node.rdatasets:
                        rtype = dns.rdatatype.to_text(rdataset.rdtype)
                        for rdata in rdataset:
                            rec = DNSRecord(
                                name=str(name),
                                record_type=rtype,
                                value=str(rdata),
                                ttl=rdataset.ttl,
                                source="axfr",
                            )
                            records.append(rec)
                            self._add_record(rec)
                _log.info("[bold green]Zone transfer SUCCESS[/] from %s — %d records", ns, len(records))
            except dns.exception.FormError:
                _log.info("AXFR refused by %s", ns)
            except (ConnectionRefusedError, OSError, socket.error) as exc:
                _log.debug("AXFR connection error for %s: %s", ns, exc)
            except Exception as exc:
                _log.debug("AXFR failed against %s: %s", ns, exc)
        return records

    # ------------------------------------------------------------------ #
    # Record enumeration                                                   #
    # ------------------------------------------------------------------ #

    def enumerate_records(self) -> list[DNSRecord]:
        """
        Query all standard DNS record types for the domain.

        Returns:
            List of DNSRecord objects found.
        """
        records: list[DNSRecord] = []
        resolver = self._make_resolver()
        for rtype in _RECORD_TYPES:
            try:
                answers = resolver.resolve(self.domain, rtype, raise_on_no_answer=False)
                for rdata in answers:
                    rec = DNSRecord(
                        name=self.domain,
                        record_type=rtype,
                        value=str(rdata),
                        ttl=answers.ttl,
                        source="direct",
                    )
                    records.append(rec)
                    self._add_record(rec)
                    _log.debug("%s %s → %s (TTL=%d)", self.domain, rtype, str(rdata), answers.ttl)
                self._evasion_sleep()
            except dns.resolver.NoAnswer:
                pass
            except dns.resolver.NXDOMAIN:
                _log.debug("NXDOMAIN for %s type %s", self.domain, rtype)
            except dns.resolver.NoNameservers:
                _log.warning("No nameservers for %s type %s", self.domain, rtype)
            except Exception as exc:
                _log.debug("Record query failed %s %s: %s", self.domain, rtype, exc)
        return records

    # ------------------------------------------------------------------ #
    # Wildcard detection                                                   #
    # ------------------------------------------------------------------ #

    def check_wildcard(self) -> bool:
        """
        Detect wildcard DNS by probing 3 random subdomains.

        Returns:
            True if domain uses wildcard DNS.
        """
        resolver = self._make_resolver()
        probe_ips: list[set[str]] = []
        for _ in range(3):
            rand_sub = "".join(random.choices(string.ascii_lowercase, k=12))
            fqdn = f"{rand_sub}.{self.domain}"
            try:
                answers = resolver.resolve(fqdn, "A")
                ips = {str(r) for r in answers}
                probe_ips.append(ips)
            except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer):
                probe_ips.append(set())
            except Exception:
                probe_ips.append(set())
            time.sleep(0.1)

        non_empty = [s for s in probe_ips if s]
        if len(non_empty) >= 2 and non_empty[0] == non_empty[1]:
            self._is_wildcard = True
            self._wildcard_ips = non_empty[0]
            _log.warning(
                "Wildcard DNS detected for %s → %s (brute-force results will be filtered)",
                self.domain,
                self._wildcard_ips,
            )
            return True
        return False

    # ------------------------------------------------------------------ #
    # Subdomain brute-force                                                #
    # ------------------------------------------------------------------ #

    def _load_wordlist(self) -> list[str]:
        path = self._wordlist_path
        if path is None:
            path = Path(__file__).parent.parent / "data" / "wordlists" / "subdomains_top5000.txt"
        if path.exists():
            words = [l.strip() for l in path.read_text(encoding="utf-8").splitlines() if l.strip()]
            _log.debug("Loaded wordlist: %d entries from %s", len(words), path)
            return words
        _log.warning("Wordlist not found at %s; using built-in minimal list", path)
        return [
            "www", "mail", "ftp", "admin", "api", "dev", "staging", "test",
            "vpn", "smtp", "pop", "imap", "webmail", "portal", "ns1", "ns2",
            "mx", "auth", "sso", "login", "dashboard", "app", "cdn", "static",
            "beta", "git", "jenkins", "ci", "jira", "wiki", "docs", "support",
            "blog", "shop", "store", "m", "mobile", "old", "new", "backup",
            "db", "database", "mysql", "redis", "mongo", "elastic", "search",
        ]

    def _probe_subdomain(self, subdomain: str) -> DNSRecord | None:
        """Resolve a single subdomain; return None if not found or wildcard."""
        fqdn = f"{subdomain}.{self.domain}"
        resolver = self._make_resolver()
        try:
            answers = resolver.resolve(fqdn, "A")
            ips = {str(r) for r in answers}
            if self._is_wildcard and ips <= self._wildcard_ips:
                return None
            self._evasion_sleep()
            ttl = answers.ttl
            return DNSRecord(name=fqdn, record_type="A", value=", ".join(sorted(ips)), ttl=ttl, source="brute")
        except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer):
            return None
        except dns.resolver.Timeout:
            return None
        except Exception as exc:
            _log.debug("Probe %s failed: %s", fqdn, exc)
            return None

    def subdomain_bruteforce(
        self,
        wordlist: list[str] | None = None,
        threads: int | None = None,
    ) -> list[DNSRecord]:
        """
        Multi-threaded subdomain brute-force with wildcard filtering.

        Args:
            wordlist: Optional list of subdomain prefixes.
            threads: Worker thread count (defaults to config.threads).

        Returns:
            List of resolved subdomain DNSRecord entries.
        """
        self.check_wildcard()
        words = wordlist or self._load_wordlist()
        n_threads = min(threads or self.config.threads, 100)
        found: list[DNSRecord] = []

        _log.info("Brute-forcing %d subdomains with %d threads", len(words), n_threads)

        with make_progress("Subdomain brute-force") as progress:
            task = progress.add_task("Subdomains", total=len(words))
            with ThreadPoolExecutor(max_workers=n_threads) as pool:
                futures = {pool.submit(self._probe_subdomain, w): w for w in words}
                for fut in as_completed(futures):
                    progress.advance(task)
                    rec = fut.result()
                    if rec:
                        found.append(rec)
                        self._add_record(rec)
                        _log.info("[bold green]+[/] %s → %s", rec.name, rec.value)
        return found

    # ------------------------------------------------------------------ #
    # Reverse DNS sweep                                                    #
    # ------------------------------------------------------------------ #

    def reverse_lookup_range(self, cidr: str) -> list[DNSRecord]:
        """
        Perform reverse DNS lookup for every IP in a CIDR range.

        Args:
            cidr: Network in CIDR notation (e.g. '192.168.1.0/24').

        Returns:
            List of PTR DNSRecord entries for hosts that resolve.
        """
        try:
            net = ipaddress.ip_network(cidr, strict=False)
        except ValueError as exc:
            _log.error("Invalid CIDR %s: %s", cidr, exc)
            return []

        found: list[DNSRecord] = []
        hosts = list(net.hosts())
        _log.info("Reverse DNS sweep over %s (%d hosts)", cidr, len(hosts))

        def _reverse(ip_obj):
            try:
                rev_name = dns.reversename.from_address(str(ip_obj))
                resolver = self._make_resolver()
                answers = resolver.resolve(rev_name, "PTR")
                for rdata in answers:
                    rec = DNSRecord(
                        name=str(rev_name),
                        record_type="PTR",
                        value=str(rdata).rstrip("."),
                        ttl=answers.ttl,
                        source="reverse",
                    )
                    self._add_record(rec)
                    return rec
            except Exception:
                return None

        with make_progress("Reverse DNS") as progress:
            task = progress.add_task("PTR lookup", total=len(hosts))
            with ThreadPoolExecutor(max_workers=self.config.threads) as pool:
                futures = {pool.submit(_reverse, ip): ip for ip in hosts}
                for fut in as_completed(futures):
                    progress.advance(task)
                    rec = fut.result()
                    if rec:
                        found.append(rec)
                        _log.debug("PTR %s → %s", rec.name, rec.value)
        return found

    # ------------------------------------------------------------------ #
    # DNS cache snooping                                                   #
    # ------------------------------------------------------------------ #

    def cache_snoop(self, targets: list[str] | None = None) -> list[dict[str, Any]]:
        """
        Check if a resolver has cached records for high-value targets.

        Non-recursive queries (RD=0) detect if a specific resolver has
        recently visited a domain, hinting at network activity patterns.

        Args:
            targets: Optional list of domains to probe.

        Returns:
            List of dicts with domain, cached status, and TTL.
        """
        targets = targets or _HIGH_VALUE_TARGETS
        results: list[dict[str, Any]] = []
        resolver_ip = random.choice(self._resolver_pool)

        for domain in targets:
            try:
                request = dns.message.make_query(domain, dns.rdatatype.A)
                request.flags &= ~dns.flags.RD  # Non-recursive
                response = dns.query.udp(request, resolver_ip, timeout=self.config.timeout)
                cached = len(response.answer) > 0
                ttl = response.answer[0].ttl if cached else 0
                results.append({"domain": domain, "cached": cached, "ttl": ttl, "resolver": resolver_ip})
                if cached:
                    _log.info("Cache hit: [bold]%s[/] (TTL=%d)", domain, ttl)
            except Exception as exc:
                _log.debug("Cache snoop failed for %s: %s", domain, exc)
            self._evasion_sleep()
        return results

    # ------------------------------------------------------------------ #
    # DNSSEC validation                                                    #
    # ------------------------------------------------------------------ #

    def check_dnssec(self) -> dict[str, Any]:
        """
        Check for DNSSEC deployment (DS, DNSKEY, RRSIG records).

        Returns:
            Dict with dnssec_enabled, has_ds, has_dnskey, has_rrsig.
        """
        resolver = self._make_resolver()
        result: dict[str, Any] = {
            "dnssec_enabled": False,
            "has_ds": False,
            "has_dnskey": False,
            "has_rrsig": False,
        }
        for rtype, key in [("DNSKEY", "has_dnskey"), ("DS", "has_ds"), ("RRSIG", "has_rrsig")]:
            try:
                ans = resolver.resolve(self.domain, rtype, raise_on_no_answer=False)
                if ans.rrset:
                    result[key] = True
                    _log.debug("DNSSEC record %s found for %s", rtype, self.domain)
            except Exception:
                pass
        result["dnssec_enabled"] = result["has_dnskey"]
        return result

    # ------------------------------------------------------------------ #
    # DNS-over-HTTPS fallback                                              #
    # ------------------------------------------------------------------ #

    def doh_lookup(self, name: str, rtype: str = "A") -> list[str]:
        """
        Resolve a name via DNS-over-HTTPS (Cloudflare or Google).

        Args:
            name: Hostname to resolve.
            rtype: DNS record type.

        Returns:
            List of answer strings.
        """
        if not self.config.dns_use_doh:
            return []
        endpoint = random.choice(_DOH_ENDPOINTS)
        url = f"{endpoint}?name={name}&type={rtype}"
        try:
            req = urllib.request.Request(
                url,
                headers={"Accept": "application/dns-json"},
            )
            with urllib.request.urlopen(req, timeout=self.config.timeout) as resp:
                data = json.loads(resp.read())
                answers = data.get("Answer", [])
                return [a["data"] for a in answers]
        except Exception as exc:
            _log.debug("DoH lookup failed for %s: %s", name, exc)
            return []

    # ------------------------------------------------------------------ #
    # Full enumeration pipeline                                            #
    # ------------------------------------------------------------------ #

    def run_full(
        self,
        do_zone: bool = True,
        do_brute: bool = True,
        do_records: bool = True,
        do_dnssec: bool = True,
        reverse_cidr: str | None = None,
    ) -> dict[str, Any]:
        """
        Run all enumeration methods and return a consolidated report dict.

        Args:
            do_zone: Attempt zone transfers.
            do_brute: Run subdomain brute-force.
            do_records: Enumerate all record types.
            do_dnssec: Check DNSSEC status.
            reverse_cidr: Optional CIDR for reverse DNS sweep.

        Returns:
            Dict with keys: domain, records, subdomains, zone_transfer,
            dnssec, cache_snoop, reverse_dns.
        """
        _log.info("[bold cyan]DNS enumeration starting for %s[/]", self.domain)
        report: dict[str, Any] = {
            "domain": self.domain,
            "records": [],
            "subdomains": [],
            "zone_transfer": [],
            "dnssec": {},
            "cache_snoop": [],
            "reverse_dns": [],
        }

        if do_records:
            recs = self.enumerate_records()
            report["records"] = [
                {"name": r.name, "type": r.record_type, "value": r.value, "ttl": r.ttl}
                for r in recs
            ]

        if do_zone:
            zt_recs = self.zone_transfer()
            report["zone_transfer"] = [
                {"name": r.name, "type": r.record_type, "value": r.value, "ttl": r.ttl}
                for r in zt_recs
            ]

        if do_brute:
            subs = self.subdomain_bruteforce()
            report["subdomains"] = [
                {"fqdn": r.name, "ips": r.value, "ttl": r.ttl}
                for r in subs
            ]

        if do_dnssec:
            report["dnssec"] = self.check_dnssec()

        if reverse_cidr:
            rev = self.reverse_lookup_range(reverse_cidr)
            report["reverse_dns"] = [
                {"ip": r.name, "hostname": r.value, "ttl": r.ttl}
                for r in rev
            ]

        _log.info(
            "[bold green]DNS enumeration complete[/]: %d records, %d subdomains, %d zone transfer entries",
            len(report["records"]),
            len(report["subdomains"]),
            len(report["zone_transfer"]),
        )
        return report

    def results(self) -> list[DNSRecord]:
        """Return deduplicated accumulated results."""
        with self._lock:
            seen: set[tuple] = set()
            deduped: list[DNSRecord] = []
            for r in self._results:
                key = (r.name, r.record_type, r.value)
                if key not in seen:
                    seen.add(key)
                    deduped.append(r)
            return sorted(deduped, key=lambda r: (r.name, r.record_type))
