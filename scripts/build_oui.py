#!/usr/bin/env python3
"""Regenerate / expand recon/data/oui_subset.csv.

The repo ships a small curated subset of common OUIs (virtualization backends
and mainstream NIC vendors) so MAC-vendor attribution works offline out of the
box. For full coverage, download the IEEE OUI registry (or the Wireshark
`manuf` file) and run this script to emit a complete PREFIX,Vendor CSV.

Usage:
    # From a local IEEE oui.csv (https://standards-oui.ieee.org/oui/oui.csv):
    python scripts/build_oui.py --ieee-csv path/to/oui.csv --out recon/data/oui_full.csv

    # From a Wireshark manuf file:
    python scripts/build_oui.py --manuf path/to/manuf --out recon/data/oui_full.csv

The scanner (recon/modules/host_discovery.py) reads whichever CSV the config
points at; both files use the same `PREFIX,Vendor` format where PREFIX is the
24-bit OUI as 6 hex chars (separators are stripped on load).
"""

from __future__ import annotations

import argparse
import csv
import sys
from pathlib import Path


def _norm_prefix(value: str) -> str:
    return value.upper().replace("-", "").replace(":", "").replace(".", "").strip()[:6]


def from_ieee_csv(path: Path) -> list[tuple[str, str]]:
    rows: list[tuple[str, str]] = []
    with open(path, encoding="utf-8", errors="replace", newline="") as f:
        reader = csv.DictReader(f)
        for row in reader:
            # IEEE columns: Registry,Assignment,Organization Name,Organization Address
            assignment = row.get("Assignment") or row.get("assignment") or ""
            org = row.get("Organization Name") or row.get("organization name") or ""
            prefix = _norm_prefix(assignment)
            if len(prefix) == 6 and org:
                rows.append((prefix, org.strip()))
    return rows


def from_manuf(path: Path) -> list[tuple[str, str]]:
    rows: list[tuple[str, str]] = []
    with open(path, encoding="utf-8", errors="replace") as f:
        for line in f:
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            parts = line.split(None, 2)
            if len(parts) < 2:
                continue
            prefix = _norm_prefix(parts[0])
            if len(prefix) != 6:
                continue  # skip 28/36-bit blocks for this flat format
            vendor = (parts[2] if len(parts) > 2 else parts[1]).strip()
            rows.append((prefix, vendor))
    return rows


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    src = ap.add_mutually_exclusive_group(required=True)
    src.add_argument("--ieee-csv", type=Path, help="IEEE oui.csv path")
    src.add_argument("--manuf", type=Path, help="Wireshark manuf file path")
    ap.add_argument("--out", type=Path, required=True, help="output CSV path")
    args = ap.parse_args(argv)

    rows = from_ieee_csv(args.ieee_csv) if args.ieee_csv else from_manuf(args.manuf)
    # de-dup, keep first
    seen: set[str] = set()
    uniq: list[tuple[str, str]] = []
    for prefix, vendor in rows:
        if prefix not in seen:
            seen.add(prefix)
            uniq.append((prefix, vendor))
    uniq.sort()

    args.out.parent.mkdir(parents=True, exist_ok=True)
    with open(args.out, "w", encoding="utf-8", newline="") as f:
        w = csv.writer(f)
        w.writerow(["PREFIX", "Vendor"])
        w.writerows(uniq)
    print(f"wrote {len(uniq)} OUI entries -> {args.out}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
