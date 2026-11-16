"""Logger robustness: untrusted strings must never break Rich rendering."""

from __future__ import annotations

from recon.core.logger import print_findings_table, safe


def test_print_findings_table_survives_markup_in_untrusted_fields():
    # Banners/descriptions are target-controlled and may contain Rich markup.
    hostile = [
        {
            "severity": "high",
            "cve": "[red]CVE-2021-0000[/red]",
            "service": "http [not-a-tag]",
            "port": 80,
            "description": "banner: Server: evil/[/] [bold]x[/bold] ]unbalanced[",
        },
        {"severity": "weird-sev", "description": "no closing bracket ["},
    ]
    # Must not raise MarkupError or anything else.
    print_findings_table(hostile, title="hostile")


def test_safe_wraps_markup_literally():
    from rich.text import Text

    t = safe("[bold]x[/bold]")
    assert isinstance(t, Text)
    # The literal string is preserved verbatim, not parsed as markup.
    assert str(t) == "[bold]x[/bold]"
