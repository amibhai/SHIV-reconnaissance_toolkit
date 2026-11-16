"""
recon.core.cpe — best-effort CPE 2.3 identifier generation.

A CPE (Common Platform Enumeration) string is the standard identifier used to
correlate a detected product+version against vulnerability feeds (NVD, OSV,
scanners). Emitting a CPE on findings/services lets downstream tooling do that
correlation. Generation is heuristic and fail-safe: an unknown product yields a
wildcard CPE, and any error yields "".
"""

from __future__ import annotations

import re

from recon.core.versioning import extract as _extract_version

__all__ = ["to_cpe"]

# product token found in a service name / banner -> (vendor, product)
_PRODUCTS: dict[str, tuple[str, str]] = {
    "apache": ("apache", "http_server"),
    "httpd": ("apache", "http_server"),
    "tomcat": ("apache", "tomcat"),
    "nginx": ("nginx", "nginx"),
    "iis": ("microsoft", "internet_information_services"),
    "microsoft-iis": ("microsoft", "internet_information_services"),
    "openssh": ("openbsd", "openssh"),
    "dropbear": ("dropbear_ssh_project", "dropbear_ssh"),
    "vsftpd": ("vsftpd_project", "vsftpd"),
    "proftpd": ("proftpd", "proftpd"),
    "pure-ftpd": ("pureftpd", "pure-ftpd"),
    "exim": ("exim", "exim"),
    "postfix": ("postfix", "postfix"),
    "sendmail": ("sendmail", "sendmail"),
    "mysql": ("oracle", "mysql"),
    "mariadb": ("mariadb", "mariadb"),
    "postgresql": ("postgresql", "postgresql"),
    "redis": ("redis", "redis"),
    "mongodb": ("mongodb", "mongodb"),
    "memcached": ("memcached", "memcached"),
    "elasticsearch": ("elastic", "elasticsearch"),
    "openssl": ("openssl", "openssl"),
    "samba": ("samba", "samba"),
    "jenkins": ("jenkins", "jenkins"),
    "gitlab": ("gitlab", "gitlab"),
    "confluence": ("atlassian", "confluence"),
    "jira": ("atlassian", "jira"),
    "docker": ("docker", "docker"),
    "kubernetes": ("kubernetes", "kubernetes"),
    "rabbitmq": ("vmware", "rabbitmq"),
    "couchdb": ("apache", "couchdb"),
    "cassandra": ("apache", "cassandra"),
    "zookeeper": ("apache", "zookeeper"),
    "lighttpd": ("lighttpd", "lighttpd"),
    "haproxy": ("haproxy", "haproxy"),
    "squid": ("squid-cache", "squid"),
}


def _clean(value: str) -> str:
    v = re.sub(r"[^a-z0-9._-]", "_", (value or "").strip().lower())
    return v or "*"


def to_cpe(service: str = "", version: str = "", banner: str = "",
           vendor: str = "", product: str = "") -> str:
    """Return a best-effort CPE 2.3 URI, or "" if nothing can be said.

    e.g. to_cpe(service="http", banner="Server: Apache/2.4.49")
         -> "cpe:2.3:a:apache:http_server:2.4.49:*:*:*:*:*:*:*"
    """
    try:
        haystack = f"{service} {product} {banner}".lower()
        vend, prod = vendor, product
        matched = product.lower() if product else ""
        if not prod:
            for token, (v, p) in _PRODUCTS.items():
                if token in haystack:
                    vend, prod, matched = (vendor or v), p, token
                    break
        if not prod:
            prod = _clean(service) if service and service != "*" else ""
        if not prod:
            return ""  # nothing identifiable
        if not vend:
            vend = prod
        # Prefer the version adjacent to the product token (banners like
        # "SSH-2.0-OpenSSH_7.4" otherwise yield the protocol version "2.0").
        ver = version
        if not ver and matched and banner:
            m = re.search(re.escape(matched) + r"[ _/v]*([0-9]+(?:\.[0-9]+)+)", banner, re.IGNORECASE)
            if m:
                ver = m.group(1)
        if not ver:
            ver = _extract_version(banner) or ""
        ver_field = _clean(ver) if ver else "*"
        return f"cpe:2.3:a:{_clean(vend)}:{_clean(prod)}:{ver_field}:*:*:*:*:*:*:*"
    except Exception:
        return ""
