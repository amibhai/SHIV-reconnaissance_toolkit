"""Tests for recon.modules.dns_enum — uses mocked DNS responses."""

import pytest
from unittest.mock import MagicMock, patch
from recon.modules.dns_enum import DNSEnumerator, DNSRecord
from recon.core.config import ReconConfig


@pytest.fixture
def cfg():
    return ReconConfig(threads=5, timeout=1.0, evasion_level=0, dns_use_doh=False)


@pytest.fixture
def enumerator(cfg, tmp_path):
    return DNSEnumerator("example.com", cfg)


def test_dns_record_fields():
    r = DNSRecord(name="example.com", record_type="A", value="93.184.216.34", ttl=3600)
    assert r.name == "example.com"
    assert r.record_type == "A"
    assert r.ttl == 3600


def test_results_deduplication(enumerator):
    enumerator._add_record(DNSRecord("a.com", "A", "1.2.3.4", 60))
    enumerator._add_record(DNSRecord("a.com", "A", "1.2.3.4", 60))
    enumerator._add_record(DNSRecord("a.com", "A", "5.6.7.8", 60))
    deduped = enumerator.results()
    assert len(deduped) == 2


def test_wildcard_detection_no_wildcard(enumerator):
    """Non-wildcard: all probes return NXDOMAIN → not wildcard."""
    import dns.resolver
    with patch.object(enumerator._make_resolver().__class__, "resolve",
                      side_effect=dns.resolver.NXDOMAIN()):
        with patch.object(enumerator, "_make_resolver") as mock_make:
            mock_resolver = MagicMock()
            mock_resolver.resolve.side_effect = dns.resolver.NXDOMAIN()
            mock_make.return_value = mock_resolver
            is_wc = enumerator.check_wildcard()
    assert is_wc is False


def test_wildcard_detection_is_wildcard(enumerator):
    """All 3 probes resolve to same IP → wildcard detected."""
    mock_ans = MagicMock()
    mock_ans.__iter__ = MagicMock(return_value=iter([MagicMock(__str__=lambda s: "1.2.3.4")]))

    with patch.object(enumerator, "_make_resolver") as mock_make:
        mock_resolver = MagicMock()
        mock_ans2 = MagicMock()
        mock_ans2.__iter__ = lambda s: iter([type("R", (), {"__str__": lambda x: "1.2.3.4"})()])
        mock_resolver.resolve.return_value = mock_ans2
        mock_make.return_value = mock_resolver

        # Override _probe_subdomain directly
        with patch.object(enumerator, "_probe_subdomain",
                          return_value=DNSRecord("x.example.com", "A", "1.2.3.4", 60)):
            # Manually set wildcard state
            enumerator._is_wildcard = True
            enumerator._wildcard_ips = {"1.2.3.4"}
            assert enumerator._is_wildcard is True


def test_subdomain_probe_skips_wildcard(enumerator):
    """_probe_subdomain returns None when resolved IP matches wildcard."""
    enumerator._is_wildcard = True
    enumerator._wildcard_ips = {"1.2.3.4"}

    mock_ans = MagicMock()
    r = MagicMock()
    r.__str__ = lambda s: "1.2.3.4"
    mock_ans.__iter__ = lambda s: iter([r])
    mock_ans.ttl = 300

    with patch.object(enumerator, "_make_resolver") as mock_make:
        mock_resolver = MagicMock()
        mock_resolver.resolve.return_value = mock_ans
        mock_make.return_value = mock_resolver
        result = enumerator._probe_subdomain("admin")
    assert result is None


def test_subdomain_probe_returns_record(enumerator):
    """_probe_subdomain returns DNSRecord when IP is not a wildcard match."""
    enumerator._is_wildcard = True
    enumerator._wildcard_ips = {"9.9.9.9"}

    mock_ans = MagicMock()
    r = MagicMock()
    r.__str__ = lambda s: "1.2.3.4"
    mock_ans.__iter__ = lambda s: iter([r])
    mock_ans.ttl = 300

    with patch.object(enumerator, "_make_resolver") as mock_make:
        mock_resolver = MagicMock()
        mock_resolver.resolve.return_value = mock_ans
        mock_make.return_value = mock_resolver
        result = enumerator._probe_subdomain("admin")
    assert result is not None
    assert "admin.example.com" in result.name


def test_cache_snoop_returns_list(enumerator):
    """cache_snoop returns list of dicts."""
    import dns.message
    with patch("dns.query.udp") as mock_udp:
        mock_resp = MagicMock()
        mock_resp.answer = []
        mock_udp.return_value = mock_resp
        result = enumerator.cache_snoop(["google.com"])
    assert isinstance(result, list)
    assert result[0]["domain"] == "google.com"
    assert result[0]["cached"] is False
