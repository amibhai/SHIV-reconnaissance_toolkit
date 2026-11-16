#!/usr/bin/env python3
r"""Generate recon/data/nmap_top_ports.txt (frequency-ordered top ports).

One port per line. The HEAD is nmap's real open-frequency ordering (ports most
likely to be open first: 80, 23, 443, 21, 22, ...), read from
scripts/nmap_top_ports_head.txt; it is followed by the remaining well-known
ports and a sequential fill, so a `topN` slice always returns exactly N ports
with the highest-value ones first. This replaces a hand-built literal that
deduped to 437 ports, which made "top1000" silently scan only 437 ports.

To refresh the HEAD authoritatively, sort nmap-services by its frequency column
(descending) and replace scripts/nmap_top_ports_head.txt.

    python scripts/build_top_ports.py
"""

from __future__ import annotations

from pathlib import Path

HERE = Path(__file__).resolve().parent
HEAD_PATH = HERE / "nmap_top_ports_head.txt"
OUT_PATH = HERE.parent / "recon" / "data" / "nmap_top_ports.txt"
TOTAL = 10000

# Important high ports to prioritize ahead of the plain sequential fill.
CURATED_HIGH = [
    1080, 1194, 1337, 1433, 1521, 1723, 1883, 2049, 2082, 2083, 2086, 2087,
    2095, 2096, 2181, 2222, 2375, 2376, 2379, 2380, 3000, 3001, 3128, 3268,
    3269, 3690, 4000, 4040, 4369, 4443, 4444, 4567, 4711, 4848, 5000, 5001,
    5044, 5060, 5061, 5222, 5269, 5432, 5433, 5555, 5601, 5672, 5900, 5901,
    5902, 5984, 5985, 5986, 6000, 6001, 6379, 6443, 6514, 6666, 6667, 7000,
    7001, 7077, 7199, 7443, 7474, 7687, 7777, 8000, 8008, 8009, 8080, 8081,
    8083, 8086, 8088, 8089, 8090, 8091, 8140, 8161, 8181, 8200, 8243, 8333,
    8443, 8500, 8530, 8531, 8600, 8686, 8800, 8834, 8888, 9000, 9001, 9002,
    9042, 9043, 9060, 9080, 9090, 9091, 9092, 9093, 9100, 9160, 9200, 9300,
    9418, 9443, 9500, 9600, 9990, 9999, 10000, 10250, 10255, 11211, 15672,
    16379, 25565, 27017, 27018, 27019, 50000, 50070, 61616,
]


def _read_head() -> list[int]:
    ports: list[int] = []
    for line in HEAD_PATH.read_text(encoding="utf-8").splitlines():
        line = line.strip()
        if line and not line.startswith("#"):
            ports.append(int(line))
    return ports


def build() -> list[int]:
    seen: set[int] = set()
    ordered: list[int] = []

    def add(p: int) -> None:
        if 1 <= p <= 65535 and p not in seen:
            seen.add(p)
            ordered.append(p)

    for p in _read_head():
        add(p)
    for p in range(1, 1024):      # remaining system ports
        add(p)
    for p in CURATED_HIGH:
        add(p)
    p = 1024                      # sequential fill for top5000 / top10000
    while len(ordered) < TOTAL and p <= 65535:
        add(p)
        p += 1
    return ordered


def main() -> int:
    ports = build()
    assert len(ports) >= TOTAL, len(ports)
    for sentinel in (22, 80, 443, 445, 3389):
        assert sentinel in ports[:1000], f"sentinel {sentinel} missing from top-1000"
    OUT_PATH.parent.mkdir(parents=True, exist_ok=True)
    OUT_PATH.write_text("\n".join(str(p) for p in ports) + "\n", encoding="utf-8")
    print(f"wrote {len(ports)} ports -> {OUT_PATH}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
