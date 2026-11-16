"""Best-effort CPE 2.3 generation (fail-safe)."""

from __future__ import annotations

import pytest

from recon.core.cpe import to_cpe


@pytest.mark.parametrize("service,banner,prefix", [
    ("http", "Server: Apache/2.4.49 (Unix)", "cpe:2.3:a:apache:http_server:2.4.49"),
    ("ssh", "SSH-2.0-OpenSSH_7.4", "cpe:2.3:a:openbsd:openssh:7.4"),
    ("nginx", "Server: nginx/1.24.0", "cpe:2.3:a:nginx:nginx:1.24.0"),
    ("mysql", "5.7.38-0ubuntu0.18.04.1", "cpe:2.3:a:oracle:mysql:5.7.38"),
])
def test_to_cpe_known_products(service, banner, prefix):
    assert to_cpe(service=service, banner=banner).startswith(prefix)


def test_to_cpe_unknown_product_uses_service():
    cpe = to_cpe(service="customthing", banner="no version here")
    assert cpe == "cpe:2.3:a:customthing:customthing:*:*:*:*:*:*:*:*"


def test_to_cpe_empty_and_failsafe():
    assert to_cpe() == ""
    assert isinstance(to_cpe(service=None, banner=None), str)  # no raise


def test_vuln_finding_carries_cpe(tmp_path):
    from recon.core.config import ReconConfig
    from recon.modules.vuln_scan import VulnScanner, _load_databases

    _load_databases()
    sc = VulnScanner("127.0.0.1", ReconConfig(output_dir=tmp_path, verbosity=0))
    out = sc.check_service_vulns(80, "Server: Apache/2.4.49 (Unix)", "apache")
    cpes = [f.to_dict()["cpe"] for f in out]
    assert any(c.startswith("cpe:2.3:a:apache:http_server:2.4.49") for c in cpes)
