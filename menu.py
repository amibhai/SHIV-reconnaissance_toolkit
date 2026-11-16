#!/usr/bin/env python3
"""
menu.py — interactive entry point.

Thin shim kept for muscle memory (`python menu.py`). The real menu lives in
recon.tui and runs over the same engine + registry + reporting pipeline as the
CLI, so menu scans now produce JSON/HTML/SARIF/NDJSON reports like every other
path. (This replaces the old ~1400-line menu that drove a separate, report-less
legacy `tools/*` engine.)
"""

from recon.tui import main

if __name__ == "__main__":
    main()
