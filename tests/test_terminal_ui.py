"""Terminal design system — real rendering behavior, no color when degraded."""

from __future__ import annotations

import io

from engine.ui.terminal import NEON_ORANGE, Console, palette, sev_rank, severity_tag, truncate_visible, visible_width


def make_console() -> tuple[Console, io.StringIO]:
    buf = io.StringIO()
    console = Console(stream=buf, silent=False)
    console.live = False  # deterministic: no carriage-control paths
    return console, buf


def test_severity_tags_are_uppercase_and_padded():
    tag = severity_tag("critical")
    assert "CRITICAL" in tag
    assert severity_tag("High") == severity_tag("high")


def test_sev_rank_ordering():
    assert sev_rank("critical") < sev_rank("high") < sev_rank("medium") < sev_rank("low") < sev_rank("info")


def test_phase_header_bracketed():
    console, buf = make_console()
    console.phase(1, 4, "RECON PHASE", "🔍")
    out = buf.getvalue()
    assert "[1/4]" in out
    assert "RECON PHASE" in out


def test_table_renders_borders_and_headers():
    console, buf = make_console()
    console.table(["SEV", "FINDING"], [["HIGH", "SQL Injection"]])
    out = buf.getvalue()
    assert "┌" in out and "│" in out and "└" in out
    assert "SEV" in out.upper() and "FINDING" in out.upper()


def test_table_uses_ascii_when_explicitly_requested(monkeypatch):
    monkeypatch.setenv("ARBALEST_ASCII", "1")
    console, buf = make_console()
    console.table(["SEV", "FINDING"], [["HIGH", "SQL Injection"]])
    out = buf.getvalue()
    assert "+" in out and "|" in out
    assert "┌" not in out and "│" not in out


def test_table_empty_state():
    console, buf = make_console()
    console.table(["A"], [])
    assert "no records" in buf.getvalue()


def test_kv_lines_align_keys():
    console, buf = make_console()
    console.kv("TARGET", "/repo")
    out = buf.getvalue()
    assert "TARGET" in out and "/repo" in out


def test_truncate_visible_respects_width():
    long = "A" * 100
    truncated = truncate_visible(long, 20)
    assert visible_width(truncated) <= 20
    assert "…" in truncated


def test_visible_width_strips_ansi():
    styled = "\x1b[38;2;255;92;26mHIGH\x1b[0m"
    assert visible_width(styled) == 4


def test_palette_emits_standard_true_color_and_preserves_visible_width():
    previous = palette.enabled
    palette.enabled = True
    try:
        styled = palette("HIGH", NEON_ORANGE, bold=True)
        assert "\x1b[1;38;2;255;92;26m" in styled
        assert visible_width(styled) == 4
    finally:
        palette.enabled = previous


def test_silent_console_emits_nothing():
    buf = io.StringIO()
    console = Console(stream=buf, silent=True)
    console.line("classified")
    console.rule()
    console.verdict({"high": 1}, 1, 1, "x.sarif", 1.0)
    assert buf.getvalue() == ""


def test_verdict_debrief_rendering():
    console, buf = make_console()
    console.verdict({"critical": 2, "high": 1}, 3, 1, "arbalest-report.sarif", 4.2)
    out = buf.getvalue()
    assert "VULNERABLE" in out
    assert "arbalest-report.sarif" in out
    assert "EXIT CODE: 1" in out


def test_verdict_secured_rendering():
    console, buf = make_console()
    console.verdict({}, 0, 0, None, 1.0)
    out = buf.getvalue()
    assert "SECURED" in out
    assert "EXIT CODE: 0" in out


def test_palette_passthrough_when_disabled():
    palette.enabled = False
    assert palette("plain", "#FF0000", bold=True) == "plain"


def test_proposed_patch_debrief_never_claims_secured():
    """An unverified patch is a proposal, not a secured codebase."""
    console, buf = make_console()
    console.verdict({}, 0, 0, "arbalest-fix-CWE-78.patch", 2.0,
                    headline="PATCH PROPOSED — NOT YET VERIFIED", path_label="PATCH FILE")
    out = buf.getvalue()
    assert "PATCH PROPOSED — NOT YET VERIFIED" in out
    assert "PATCH FILE" in out and "arbalest-fix-CWE-78.patch" in out
    assert "SECURED" not in out.replace("0 = SECURED", "")
    assert "SARIF REPORT" not in out


def test_banner_spells_arbalest_not_another_product():
    from engine.ui.terminal import LOGO

    assert len(LOGO) == 6
    # Every row is the same eight-letter word; 65 columns once the T is added.
    assert max(len(row) for row in LOGO) <= 76
    console, buf = make_console()
    console.hero("1.0.0", "nebius", "m", "SANDBOX", "t")
    assert "TRIAL CLASS" not in buf.getvalue()

