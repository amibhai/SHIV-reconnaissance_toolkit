"""
recon.core.versioning — tolerant version parsing and range checks.

Used to gate CVE matches by affected version so a rule does not fire on a
product name alone (the main source of banner-match false positives). Every
function is fail-safe: it never raises on odd input — a value it cannot parse
simply does not satisfy a constraint.
"""

from __future__ import annotations

import re

__all__ = ["extract", "parse", "compare", "satisfies"]

_VERSION_RE = re.compile(r"(\d+(?:\.\d+){0,3})")
_CLAUSE_RE = re.compile(r"(<=|>=|==|!=|=|<|>)\s*(.+)")


def extract(text: str | None) -> str | None:
    """Return the first dotted numeric version found in ``text`` (or None)."""
    if not text:
        return None
    m = _VERSION_RE.search(str(text))
    return m.group(1) if m else None


def parse(version: str) -> tuple[int, ...]:
    """Parse a dotted version into an int tuple; non-numeric parts become 0."""
    parts: list[int] = []
    for part in str(version).split("."):
        m = re.match(r"\d+", part.strip())
        parts.append(int(m.group()) if m else 0)
    return tuple(parts) if parts else (0,)


def compare(a: str, b: str) -> int:
    """Return -1/0/1 comparing two versions (shorter is zero-padded)."""
    ta, tb = parse(a), parse(b)
    n = max(len(ta), len(tb))
    ta = ta + (0,) * (n - len(ta))
    tb = tb + (0,) * (n - len(tb))
    return (ta > tb) - (ta < tb)


def satisfies(version: str, constraint: str) -> bool:
    """True if ``version`` meets ``constraint``.

    Constraint is comma-separated clauses, all of which must hold, e.g.
    ">=2.4.0,<2.4.50", "==2.3.4", "<7.7", "<=1.2.3". Never raises; returns
    False on any unparseable input (conservative — the rule won't fire).
    """
    try:
        ver = extract(version) or version
        if not ver:
            return False
        for clause in str(constraint).split(","):
            clause = clause.strip()
            if not clause:
                continue
            m = _CLAUSE_RE.match(clause)
            if not m:
                return False
            op, rhs = m.group(1), m.group(2).strip()
            c = compare(ver, rhs)
            ok = {
                "<": c < 0, "<=": c <= 0, ">": c > 0, ">=": c >= 0,
                "==": c == 0, "=": c == 0, "!=": c != 0,
            }[op]
            if not ok:
                return False
        return True
    except Exception:
        return False
