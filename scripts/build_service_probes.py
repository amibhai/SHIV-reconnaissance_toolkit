#!/usr/bin/env python3
"""Generate recon/data/service_probes.json from a readable source of truth.

This is the authoritative, human-editable definition of the service-detection
probes. Binary probes are written here as Python ``bytes`` literals (readable,
reviewable); text probes are plain strings and may use the ``{target}``
placeholder. The generator emits valid JSON, base64-encoding the binary probes
so the on-disk file is always parseable (the old hand-written file used raw
``\\xNN`` escapes and was invalid JSON, silently disabling service detection).

Run from the repo root:   python scripts/build_service_probes.py
It validates every probe before writing and refuses to emit a broken file.
"""

from __future__ import annotations

import base64
import json
import re
import sys
from pathlib import Path

OUT_PATH = Path(__file__).resolve().parent.parent / "recon" / "data" / "service_probes.json"

# name, protocol, ports, probe (bytes=binary / str=text, may use {target}), match_regex, service
PROBES: list[dict] = [
    dict(name="HTTP", protocol="tcp", ports=[80, 8080, 8000, 8008, 8888],
         probe="GET / HTTP/1.0\r\nHost: {target}\r\nUser-Agent: Mozilla/5.0\r\n\r\n",
         match_regex=r"Server: (?P<version>[^\r\n]+)", service_name="http"),
    dict(name="HTTPS", protocol="tcp", ports=[443, 8443, 4443],
         probe="HEAD / HTTP/1.0\r\nHost: {target}\r\n\r\n",
         match_regex=r"Server: (?P<version>[^\r\n]+)", service_name="https"),
    dict(name="SSH", protocol="tcp", ports=[22, 2222, 22222],
         probe="", match_regex=r"(?P<version>SSH-\S+)", service_name="ssh"),
    dict(name="FTP", protocol="tcp", ports=[21, 2121],
         probe="", match_regex=r"220[- ](?P<version>[^\r\n]+)", service_name="ftp"),
    dict(name="SMTP", protocol="tcp", ports=[25, 587, 465],
         probe="EHLO recon.local\r\n",
         match_regex=r"220[- ](?P<version>[^\r\n]+)", service_name="smtp"),
    dict(name="POP3", protocol="tcp", ports=[110, 995],
         probe="", match_regex=r"\+OK (?P<version>[^\r\n]+)", service_name="pop3"),
    dict(name="IMAP", protocol="tcp", ports=[143, 993],
         probe="", match_regex=r"\* OK (?P<version>[^\r\n]+)", service_name="imap"),
    dict(name="MySQL", protocol="tcp", ports=[3306],
         probe="", match_regex=r"(?P<version>\d+\.\d+\.\d+[^\x00]*)", service_name="mysql"),
    dict(name="PostgreSQL", protocol="tcp", ports=[5432, 5433],
         probe="", match_regex=r"(?P<version>PostgreSQL[^\x00]+)", service_name="postgresql"),
    dict(name="Redis", protocol="tcp", ports=[6379, 6380],
         probe="INFO server\r\n",
         match_regex=r"redis_version:(?P<version>[^\r\n]+)", service_name="redis"),
    dict(name="MongoDB", protocol="tcp", ports=[27017, 27018, 27019],
         probe="", match_regex=r"MongoDB[/ ](?P<version>[\d\.]+)", service_name="mongodb"),
    dict(name="Elasticsearch", protocol="tcp", ports=[9200, 9300],
         probe="GET / HTTP/1.0\r\nHost: {target}\r\n\r\n",
         match_regex=r'"number"\s*:\s*"(?P<version>[\d\.]+)"', service_name="elasticsearch"),
    dict(name="Memcached", protocol="tcp", ports=[11211],
         probe="version\r\n", match_regex=r"VERSION (?P<version>[^\r\n]+)", service_name="memcached"),
    dict(name="RDP", protocol="tcp", ports=[3389],
         probe="", match_regex=r"(?P<version>\x03\x00)", service_name="rdp"),
    dict(name="VNC", protocol="tcp", ports=[5900, 5901, 5902],
         probe="", match_regex=r"RFB (?P<version>[\d\.]+)", service_name="vnc"),
    dict(name="Telnet", protocol="tcp", ports=[23],
         probe="", match_regex=r"(?P<version>[^\r\n]{3,80})", service_name="telnet"),
    dict(name="SMB", protocol="tcp", ports=[139, 445],
         probe="", match_regex=r"(?P<version>SMB|NTLM|Windows)", service_name="smb"),
    dict(name="LDAP", protocol="tcp", ports=[389, 636],
         probe=b"\x30\x0c\x02\x01\x01\x60\x07\x02\x01\x03\x04\x00\x80\x00",
         match_regex=r"(?P<version>ldap|LDAP)", service_name="ldap"),
    dict(name="Tomcat", protocol="tcp", ports=[8080, 8009, 8443],
         probe="GET / HTTP/1.0\r\nHost: {target}\r\n\r\n",
         match_regex=r"Apache Tomcat/(?P<version>[\d\.]+)", service_name="tomcat"),
    dict(name="IIS", protocol="tcp", ports=[80, 443, 8080],
         probe="HEAD / HTTP/1.0\r\nHost: {target}\r\n\r\n",
         match_regex=r"Microsoft-IIS/(?P<version>[\d\.]+)", service_name="iis"),
    dict(name="Jenkins", protocol="tcp", ports=[8080, 8443, 50000],
         probe="GET / HTTP/1.0\r\nHost: {target}\r\n\r\n",
         match_regex=r"X-Jenkins: (?P<version>[\d\.]+)", service_name="jenkins"),
    dict(name="GitLab", protocol="tcp", ports=[80, 443],
         probe="GET /users/sign_in HTTP/1.0\r\nHost: {target}\r\n\r\n",
         match_regex=r"GitLab(?:EE)?[/ ](?P<version>[\d\.]+)", service_name="gitlab"),
    dict(name="RabbitMQ", protocol="tcp", ports=[5672, 15672, 25672],
         probe=b"AMQP\x00\x00\x09\x01",
         match_regex=r"(?P<version>AMQP|RabbitMQ)", service_name="rabbitmq"),
    dict(name="Cassandra", protocol="tcp", ports=[9042, 9160],
         probe="", match_regex=r"(?P<version>Cassandra|CQL)", service_name="cassandra"),
    dict(name="CouchDB", protocol="tcp", ports=[5984],
         probe="GET / HTTP/1.0\r\nHost: {target}\r\n\r\n",
         match_regex=r'"version":"(?P<version>[\d\.]+)"', service_name="couchdb"),
    dict(name="Docker API", protocol="tcp", ports=[2375, 2376],
         probe="GET /info HTTP/1.0\r\nHost: {target}\r\n\r\n",
         match_regex=r'"Version":"(?P<version>[^"]+)"', service_name="docker"),
    dict(name="Kubernetes API", protocol="tcp", ports=[6443, 8080, 8443],
         probe="GET /api HTTP/1.0\r\nHost: {target}\r\n\r\n",
         match_regex=r'"serverVersion":\{"major":"(?P<version>[\d]+)"', service_name="kubernetes"),
    dict(name="Rsync", protocol="tcp", ports=[873],
         probe="", match_regex=r"@RSYNCD: (?P<version>[^\r\n]+)", service_name="rsync"),
    dict(name="SNMP", protocol="udp", ports=[161, 162],
         probe=b"\x30\x26\x02\x01\x00\x04\x06public\xa0\x19\x02\x04\x00\x00\x00\x01"
               b"\x02\x01\x00\x02\x01\x00\x30\x0b\x30\x09\x06\x05\x2b\x06\x01\x02\x01\x05\x00",
         match_regex=r"(?P<version>.*)", service_name="snmp"),
    dict(name="NTP", protocol="udp", ports=[123],
         probe=b"\x1b" + b"\x00" * 47,
         match_regex=r"(?P<version>.*)", service_name="ntp"),
    dict(name="Minecraft", protocol="tcp", ports=[25565],
         probe=b"\xfe\x01",
         match_regex=r"(?P<version>\d+\.\d+[^\x00]*)", service_name="minecraft"),
    dict(name="HTTP-Proxy", protocol="tcp", ports=[3128, 8118, 8888],
         probe="GET http://www.example.com/ HTTP/1.0\r\n\r\n",
         match_regex=r"(?P<version>Squid|Privoxy|TinyProxy)[/ ]([\d\.]+)", service_name="http-proxy"),
    dict(name="X11", protocol="tcp", ports=[6000, 6001, 6002],
         probe=b"\x6c\x00\x0b\x00\x00\x00\x00\x00\x00\x00\x00\x00",
         match_regex=r"(?P<version>X11|X Window)", service_name="x11"),
    dict(name="Zookeeper", protocol="tcp", ports=[2181, 2182],
         probe="stat\n", match_regex=r"Zookeeper version: (?P<version>[^,\n]+)", service_name="zookeeper"),
]


def build() -> list[dict]:
    out: list[dict] = []
    for p in PROBES:
        raw = p["probe"]
        if isinstance(raw, bytes):
            encoding, value = "base64", base64.b64encode(raw).decode("ascii")
        else:
            encoding, value = "text", raw
        out.append({
            "name": p["name"],
            "protocol": p["protocol"],
            "ports": p["ports"],
            "probe_encoding": encoding,
            "probe": value,
            "match_regex": p["match_regex"],
            "service_name": p["service_name"],
        })
    return out


def _self_check(entries: list[dict]) -> None:
    # every regex compiles
    for e in entries:
        re.compile(e["match_regex"])
    # base64 round-trips back to the exact source bytes
    by_name = {p["name"]: p for p in PROBES}
    for e in entries:
        if e["probe_encoding"] == "base64":
            src = by_name[e["name"]]["probe"]
            assert base64.b64decode(e["probe"]) == src, f"base64 round-trip failed: {e['name']}"
    # shared loader validation agrees
    sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
    from recon.core.probes import validate_probes
    problems = validate_probes(entries)
    assert not problems, "validation failed: " + "; ".join(problems)


def main() -> int:
    entries = build()
    _self_check(entries)
    OUT_PATH.parent.mkdir(parents=True, exist_ok=True)
    with open(OUT_PATH, "w", encoding="utf-8", newline="\n") as f:
        json.dump(entries, f, indent=2, ensure_ascii=False)
        f.write("\n")
    n_bin = sum(1 for e in entries if e["probe_encoding"] == "base64")
    print(f"wrote {len(entries)} probes ({n_bin} binary/base64) -> {OUT_PATH}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
