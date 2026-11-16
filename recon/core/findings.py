"""
recon.core.findings — the canonical structured finding model.

A single, validated finding type shared by every module and the report
pipeline, replacing the free-form ``dict[str, Any]`` findings that nothing
validated (so template.html assumed keys no producer guaranteed). Living in
core, it is importable by any module without an import cycle.
"""

from __future__ import annotations

import re
from enum import Enum
from pathlib import Path

from pydantic import BaseModel, Field, model_validator

__all__ = ["Severity", "Confidence", "Finding", "load_kev"]

_CVE_RE = re.compile(r"CVE-\d{4}-\d{3,7}", re.IGNORECASE)

_SEVERITY_RANK = {"critical": 5, "high": 4, "medium": 3, "low": 2, "info": 1}

_KEV_PATH = Path(__file__).resolve().parent.parent / "data" / "cisa_kev.txt"
_kev_cache: set[str] | None = None


def load_kev() -> set[str]:
    """CVE ids in CISA's Known Exploited Vulnerabilities catalog (cached)."""
    global _kev_cache
    if _kev_cache is None:
        ids: set[str] = set()
        try:
            for line in _KEV_PATH.read_text(encoding="utf-8").splitlines():
                line = line.strip()
                if line and not line.startswith("#"):
                    ids.add(line.upper())
        except OSError:
            pass
        _kev_cache = ids
    return _kev_cache


class Severity(str, Enum):
    critical = "critical"
    high = "high"
    medium = "medium"
    low = "low"
    info = "info"

    @property
    def rank(self) -> int:
        """Numeric rank for risk-ordered sorting (critical highest)."""
        return _SEVERITY_RANK[self.value]

    @classmethod
    def coerce(cls, value: object) -> "Severity":
        """Best-effort conversion; unknown values become info rather than raise."""
        if isinstance(value, Severity):
            return value
        try:
            return cls(str(value).strip().lower())
        except ValueError:
            return cls.info


class Confidence(str, Enum):
    confirmed = "confirmed"   # verified (e.g. a successful auth / exact match)
    firm = "firm"             # strong signal (version/banner match)
    tentative = "tentative"   # heuristic / unverified


class Finding(BaseModel):
    """A single vulnerability, misconfiguration, or exposure finding."""

    id: str                                        # stable id: CVE or rule id
    title: str                                     # human-readable summary
    severity: Severity = Severity.info
    confidence: Confidence = Confidence.firm
    cve: list[str] = Field(default_factory=list)
    cvss: float | None = None
    host: str = ""
    port: int | None = None
    service: str = ""
    evidence: str = ""
    references: list[str] = Field(default_factory=list)
    remediation: str = ""
    kev: bool = False  # CVE is in CISA's Known Exploited Vulnerabilities catalog

    @model_validator(mode="after")
    def _tag_kev(self) -> "Finding":
        if not self.kev and self.cve and any(c.upper() in load_kev() for c in self.cve):
            self.kev = True
        return self

    def to_dict(self) -> dict:
        """Canonical serialization consumed by the report, HTML, CSV, SARIF, NDJSON."""
        return {
            "id": self.id,
            "title": self.title,
            "severity": self.severity.value,
            "confidence": self.confidence.value,
            "cve": list(self.cve),
            "cvss": self.cvss,
            "kev": self.kev,
            "host": self.host,
            "port": self.port,
            "service": self.service,
            "evidence": self.evidence[:500] if self.evidence else "",
            "references": list(self.references),
            "remediation": self.remediation,
        }

    @classmethod
    def from_legacy(
        cls,
        *,
        severity: object = "info",
        finding: str = "",
        service: str = "",
        port: int | None = None,
        description: str = "",
        evidence: str = "",
        remediation: str = "",
        cvss_score: float = 0.0,
        host: str = "",
        references: list[str] | None = None,
        confidence: object = Confidence.firm,
        **_ignored: object,
    ) -> "Finding":
        """Build a Finding from the old vuln_scan keyword shape.

        Mapping: finding -> id (+ any CVE ids parsed into `cve`); description ->
        title; cvss_score -> cvss (0.0 means "unset" -> None).
        """
        ident = finding or (description[:60] if description else "finding")
        try:
            conf = confidence if isinstance(confidence, Confidence) else Confidence(str(confidence).lower())
        except ValueError:
            conf = Confidence.firm
        return cls(
            id=ident,
            title=description or finding or ident,
            severity=Severity.coerce(severity),
            confidence=conf,
            cve=_CVE_RE.findall(finding or ""),
            cvss=cvss_score if cvss_score else None,
            host=host,
            port=port,
            service=service,
            evidence=evidence,
            remediation=remediation,
            references=list(references or []),
        )
