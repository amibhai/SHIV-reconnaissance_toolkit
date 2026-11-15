"""
recon.core.probes — service-detection probe loader and payload builder.

The on-disk probe database (``recon/data/service_probes.json``) drives
version/service detection. Each probe is a JSON object:

    {
      "name":           "HTTP",
      "protocol":       "tcp" | "udp",
      "ports":          [80, 8080, ...],
      "probe_encoding": "text" | "base64",
      "probe":          "<payload>",         # text (may contain {target}) or base64
      "match_regex":    "(?P<version>...)",   # optional; version in a 'version' group
      "service_name":   "http"
    }

Why ``probe_encoding``: JSON strings cannot carry raw ``\\xNN`` byte escapes, and
many real probes (LDAP bind, SNMP get, NTP, AMQP, X11, Minecraft ping) are
binary. Binary probes are therefore base64-encoded; human-readable text probes
stay as text so they remain diff-friendly and can use the ``{target}``
placeholder. The previous format stored raw ``\\xNN`` escapes, which made the
whole file invalid JSON — it failed to parse and *silently* disabled all
service detection. This loader raises instead of silently returning nothing.
"""

from __future__ import annotations

import base64
import binascii
import json
import re
import threading
from pathlib import Path
from typing import Any

from recon.core.logger import get_logger

__all__ = [
    "PROBES_PATH",
    "load_probes",
    "probe_payload",
    "validate_probes",
    "probes_for_port",
]

_log = get_logger("probes")

PROBES_PATH = Path(__file__).resolve().parent.parent / "data" / "service_probes.json"

_VALID_ENCODINGS = {"text", "base64"}
_REQUIRED_KEYS = {"name", "protocol", "ports", "probe", "probe_encoding", "service_name"}

_cache: list[dict[str, Any]] | None = None
_lock = threading.Lock()


class ProbeLoadError(RuntimeError):
    """Raised when the probe database is missing or malformed."""


def load_probes(path: Path | None = None, force: bool = False) -> list[dict[str, Any]]:
    """Load and cache the service-detection probes.

    Raises ``ProbeLoadError`` on a missing/invalid file rather than returning an
    empty list, so a broken database is a loud failure (and a failing test),
    never a silent loss of service detection.
    """
    global _cache
    target = path or PROBES_PATH
    with _lock:
        if _cache is not None and not force and path is None:
            return _cache
        if not target.exists():
            raise ProbeLoadError(f"probe database not found: {target}")
        try:
            with open(target, encoding="utf-8") as f:
                data = json.load(f)
        except json.JSONDecodeError as exc:
            raise ProbeLoadError(f"probe database is not valid JSON ({target}): {exc}") from exc
        if not isinstance(data, list):
            raise ProbeLoadError(f"probe database must be a JSON array: {target}")
        errors = validate_probes(data)
        if errors:
            raise ProbeLoadError(
                f"probe database failed validation ({target}): " + "; ".join(errors)
            )
        if path is None:
            _cache = data
        return data


def probe_payload(probe: dict[str, Any], target: str) -> bytes:
    """Return the exact bytes to send for ``probe`` against ``target``.

    - base64 probes decode to their exact bytes (binary-safe).
    - text probes substitute ``{target}`` and encode as latin-1 (1:1 byte map).
    """
    encoding = probe.get("probe_encoding", "text")
    raw = probe.get("probe", "")
    if encoding == "base64":
        return base64.b64decode(raw)
    return str(raw).replace("{target}", target).encode("latin-1", "ignore")


def probes_for_port(port: int, protocol: str = "tcp", probes: list[dict[str, Any]] | None = None):
    """Yield probes applicable to ``port``/``protocol`` (preserves file order)."""
    for probe in probes if probes is not None else load_probes():
        if probe.get("protocol", "tcp") != protocol:
            continue
        if port in probe.get("ports", []):
            yield probe


def validate_probes(probes: list[dict[str, Any]]) -> list[str]:
    """Return a list of human-readable problems; empty means valid.

    Shared by the loader and the data-integrity test, so a malformed probe can
    never reach a live scan.
    """
    errors: list[str] = []
    seen_names: set[str] = set()
    for i, probe in enumerate(probes):
        tag = probe.get("name", f"#{i}")
        missing = _REQUIRED_KEYS - probe.keys()
        if missing:
            errors.append(f"{tag}: missing keys {sorted(missing)}")
            continue
        if probe["name"] in seen_names:
            errors.append(f"{tag}: duplicate probe name")
        seen_names.add(probe["name"])
        if probe["protocol"] not in ("tcp", "udp"):
            errors.append(f"{tag}: protocol must be tcp/udp, got {probe['protocol']!r}")
        if not isinstance(probe["ports"], list) or not probe["ports"]:
            errors.append(f"{tag}: ports must be a non-empty list")
        enc = probe["probe_encoding"]
        if enc not in _VALID_ENCODINGS:
            errors.append(f"{tag}: probe_encoding must be one of {_VALID_ENCODINGS}, got {enc!r}")
        elif enc == "base64":
            try:
                decoded = base64.b64decode(probe["probe"], validate=True)
            except (binascii.Error, ValueError) as exc:
                errors.append(f"{tag}: probe is not valid base64 ({exc})")
            else:
                if b"{target}" in decoded:
                    errors.append(f"{tag}: base64 probe must not contain the {{target}} placeholder")
        regex = probe.get("match_regex")
        if regex:
            try:
                re.compile(regex)
            except re.error as exc:
                errors.append(f"{tag}: match_regex does not compile ({exc})")
    return errors
