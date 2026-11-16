"""Data-file integrity gate.

The toolkit is data-driven (CVE rules, service probes, credentials, OUI, port
lists). A malformed data file used to fail *silently* at runtime (e.g. an
invalid service_probes.json disabled all service detection with no error).
These cheap tests turn every such defect into a hard CI failure.

Sections are added as each data file is repaired across the Foundation Phase.
"""

from __future__ import annotations

import json
import re
from pathlib import Path

import pytest

DATA_DIR = Path(__file__).resolve().parents[1] / "data"


def _load_json(name: str):
    path = DATA_DIR / name
    assert path.exists(), f"missing data file: {path}"
    with open(path, encoding="utf-8") as f:
        return json.load(f)  # raises -> test fails, instead of a silent runtime []


# --- cve_db.json -----------------------------------------------------------

def test_cve_db_is_valid_json_list():
    db = _load_json("cve_db.json")
    assert isinstance(db, list) and db, "cve_db.json must be a non-empty list"


def test_cve_db_entries_have_required_fields():
    db = _load_json("cve_db.json")
    required = {"cve_id", "service", "version_regex", "cvss_score", "severity"}
    for e in db:
        missing = required - e.keys()
        assert not missing, f"{e.get('cve_id', '?')} missing fields: {missing}"


def test_every_cve_regex_compiles():
    """Regressions guard: 2 regexes used to be uncompilable and silently skipped."""
    db = _load_json("cve_db.json")
    bad = []
    for e in db:
        try:
            re.compile(e["version_regex"])
        except re.error as ex:
            bad.append(f"{e['cve_id']}: {ex}")
    assert not bad, "non-compiling CVE regex(es): " + "; ".join(bad)


def test_cve_ids_are_unique():
    db = _load_json("cve_db.json")
    ids = [e["cve_id"] for e in db]
    dupes = {i for i in ids if ids.count(i) > 1}
    assert not dupes, f"duplicate cve_id(s): {dupes}"


# --- default_creds.json ----------------------------------------------------

def test_default_creds_is_valid_json():
    creds = _load_json("default_creds.json")
    assert isinstance(creds, list) and creds
    for svc in creds:
        assert "service" in svc and "credentials" in svc
        assert isinstance(svc["credentials"], list)


# --- service_probes.json ---------------------------------------------------

def test_service_probes_load_and_validate():
    """Regression guard: the file used to be invalid JSON (raw hex-byte escapes),
    which silently disabled ALL service detection. It must now parse, validate,
    and expose the full probe set."""
    from recon.core.probes import load_probes, validate_probes

    probes = load_probes(force=True)
    assert len(probes) == 34, f"expected 34 probes, got {len(probes)}"
    assert validate_probes(probes) == []


def test_service_probes_payloads_build():
    """Every probe must produce bytes; {target} must be substituted in text."""
    from recon.core.probes import load_probes, probe_payload

    for probe in load_probes(force=True):
        payload = probe_payload(probe, "scanme.example")
        assert isinstance(payload, bytes)
        assert b"{target}" not in payload


# --- oui_subset.csv --------------------------------------------------------

def test_oui_db_present_and_parses():
    path = DATA_DIR / "oui_subset.csv"
    assert path.exists(), "oui_subset.csv missing -> MAC vendor lookup is dead"
    import csv

    with open(path, encoding="utf-8", newline="") as f:
        rows = list(csv.DictReader(f))
    assert len(rows) >= 20, f"expected a meaningful OUI subset, got {len(rows)}"
    for r in rows:
        assert len(r["PREFIX"]) == 6 and r["Vendor"]


# --- nmap_top_ports.txt ----------------------------------------------------

def test_top_ports_file_is_correct():
    """Regression guard: 'top1000' used to be 437 ports; 'top10000' was 1..10000."""
    path = DATA_DIR / "nmap_top_ports.txt"
    assert path.exists(), "nmap_top_ports.txt missing"
    ports = [int(x) for x in path.read_text(encoding="utf-8").split() if not x.startswith("#")]
    assert len(ports) >= 10000, f"need >=10000 ports, got {len(ports)}"
    assert len(ports) == len(set(ports)), "top-ports list has duplicates"
    assert all(1 <= p <= 65535 for p in ports)
    # high-value services must be inside the top-1000 slice
    for sentinel in (22, 80, 443, 445, 3389, 3306, 8080):
        assert sentinel in ports[:1000], f"{sentinel} not in top-1000"


def test_port_specs_return_correct_counts():
    from recon.modules.port_scan import _parse_port_spec

    assert len(_parse_port_spec("top20")) == 20
    assert len(_parse_port_spec("top100")) == 100
    assert len(_parse_port_spec("top1000")) == 1000
    assert len(_parse_port_spec("top5000")) == 5000
    assert len(_parse_port_spec("top10000")) == 10000


# --- cisa_kev.txt ----------------------------------------------------------

def test_kev_file_parses_and_ids_well_formed():
    import re as _re
    from recon.core.findings import load_kev

    kev = load_kev()
    assert len(kev) >= 30, f"KEV set unexpectedly small: {len(kev)}"
    assert all(_re.fullmatch(r"CVE-\d{4}-\d{3,7}", c) for c in kev)
    # sanity: famous exploited CVEs are present
    assert {"CVE-2021-44228", "CVE-2019-0708", "CVE-2020-1472"} <= kev


def test_cve_version_gating_fields_are_valid():
    """Any version_capture must compile; any version_range must be evaluable."""
    from recon.core import versioning as V

    db = _load_json("cve_db.json")
    for e in db:
        cap = e.get("version_capture")
        if cap:
            re.compile(cap)  # raises -> fail
        vr = e.get("version_range")
        if vr:
            # must be well-formed (evaluating a sample returns a bool, no raise)
            assert isinstance(V.satisfies("1.0.0", vr), bool)
            assert any(op in vr for op in ("<", ">", "=", "!"))
        conf = e.get("confidence")
        if conf:
            assert conf in ("confirmed", "firm", "tentative")
