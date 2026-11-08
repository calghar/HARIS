import re

import pytest

from haris.models import RiskPosture, Severity, Verification, VerificationTier
from haris.reporting.escape import md_code, md_fence, md_text
from haris.reporting.html_report import HTMLReporter
from haris.reporting.markdown_report import MarkdownReporter
from tests.report_sessions import make_finding, make_session

TITLE = "<img src=x onerror=alert(1)>"
EVIDENCE = "<script>alert(1)</script> [x](javascript:alert(1)) ```"
FENCED = re.compile(r"^(`{3,})\n.*?\n\1$", re.DOTALL | re.MULTILINE)


def hostile_session():
    return make_session(
        [
            make_finding(
                title=TITLE,
                description="see [x](javascript:alert(1)) <b>now</b>",
                evidence=EVIDENCE,
                request_example="curl '<script>'",
                url="https://example.com/?a=<script>&b=`x`",
                parameter="q|<svg onload=1>",
                remediation="[fix](javascript:alert(2))",
                references=["javascript:alert(3)", "https://a.example/`<i>"],
                scanner="<iframe>",
            )
        ]
    )


def prose(markdown: str) -> str:
    """The Markdown outside fenced code blocks."""
    return FENCED.sub("", markdown)


def test_markdown_neutralises_raw_html_and_links():
    md = MarkdownReporter().generate(hostile_session())
    assert "<img" not in md
    assert "<script" not in md
    assert "<svg" not in md and "<iframe" not in md and "<b>" not in md
    assert not re.search(r"\]\(javascript:", prose(md))
    assert "&lt;img src=x onerror=alert\\(1\\)&gt;" in md


def test_html_report_escapes_target_content():
    out = HTMLReporter().generate(hostile_session())
    assert "<img" not in out
    assert "<script" not in out
    assert "<svg" not in out and "<iframe" not in out and "<b>" not in out
    assert 'href="javascript' not in out
    assert "<a " not in out
    assert "&lt;img src=x onerror=alert(1)&gt;" in out
    assert "&lt;script&gt;alert(1)&lt;/script&gt;" in out
    assert "Content-Security-Policy" in out


def test_html_escapes_target_url_in_title():
    session = hostile_session()
    session.target.base_url = "https://example.com/"
    session.profile_name = '"><script>x</script>'
    assert "<script>x" not in HTMLReporter().generate(session)


def test_evidence_cannot_close_its_fence():
    block = md_fence("a\n`````\n<b>")
    assert block.startswith("``````\n") and block.endswith("\n``````")
    assert "<b>" not in block


def test_code_span_survives_backticks_and_pipes():
    span = md_code("a`b``c|d")
    assert span.startswith("```") and "\\|" in span


def test_md_text_flattens_lines_and_table_breaks():
    assert md_text("a\n| b\r\n*c*") == "a \\| b \\*c\\*"


@pytest.mark.parametrize(
    ("tier", "suppressed", "section"),
    [
        (VerificationTier.UNVERIFIED, False, "findings"),
        (VerificationTier.REPLAY_VERIFIED, False, "findings"),
        (VerificationTier.EXPLOIT_VALIDATED, False, "findings"),
        (VerificationTier.REFUTED, False, "appendix"),
        (VerificationTier.REPLAY_VERIFIED, True, "appendix"),
    ],
)
def test_visibility_by_tier(tier, suppressed, section):
    """Scenario Outline: Visibility by tier (JSON and Markdown)."""
    from haris.models import Suppression

    finding = make_finding(
        title="Marker finding",
        verification=Verification(tier=tier),
        suppression=(
            Suppression(reason="r", author="a", expires="2099-01-01")
            if suppressed
            else None
        ),
    )
    md = MarkdownReporter().generate(make_session([finding]))
    head, _, appendix = md.partition("## Appendix")
    assert ("Marker finding" in head) is (section == "findings")
    assert ("Marker finding" in appendix) is (section == "appendix")


def test_finding_shows_verification_tier_and_confidence():
    md = MarkdownReporter().generate(make_session())
    assert "| **Verification** | replay_verified (replay) |" in md
    assert "| **Confidence** | Firm (0.80) |" in md


def test_active_counts_exclude_inactive():
    md = MarkdownReporter().generate(make_session())
    assert "**1 finding(s)**" in md
    assert "2 refuted or suppressed" in md
    assert "| High | 1 |" in md and "| Medium | 1 |" not in md


def test_unknown_posture_and_unfinished_scan_are_visible():
    from haris.models import ScanState

    session = make_session([make_finding(severity=Severity.LOW)])
    session.risk_posture = RiskPosture.UNKNOWN
    session.scan_state = ScanState.FAILED
    md = MarkdownReporter().generate(session)
    assert "**Risk Posture: UNKNOWN**" in md
    assert "Scan failed" in md
