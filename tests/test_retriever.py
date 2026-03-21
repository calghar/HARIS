"""Tests for the FindingRetriever FTS5-backed search component."""

from __future__ import annotations

import sqlite3

import pytest

from src.llm.retriever import FindingRetriever
from src.models import Confidence, Finding, Severity

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _finding(
    title: str,
    description: str,
    severity: Severity = Severity.MEDIUM,
    *,
    finding_id: str | None = None,
    tags: list[str] | None = None,
    scanner: str = "test_scanner",
    url: str = "https://example.com",
    evidence: str = "",
    remediation: str = "",
) -> Finding:
    """Build a minimal Finding for test use."""
    kwargs: dict = dict(
        title=title,
        description=description,
        severity=severity,
        confidence=Confidence.FIRM,
        scanner=scanner,
        url=url,
        evidence=evidence,
        remediation=remediation,
        tags=tags or [],
    )
    if finding_id is not None:
        kwargs["finding_id"] = finding_id
    return Finding(**kwargs)


# ---------------------------------------------------------------------------
# Index construction and basic retrieval
# ---------------------------------------------------------------------------


def test_build_index_and_retrieve():
    """Keyword in title/description must surface the matching finding."""
    findings = [
        _finding(
            "SQL Injection in login",
            "The login form is injectable",
            Severity.CRITICAL,
            finding_id="f001",
        ),
        _finding(
            "Missing HSTS header",
            "Response lacks Strict-Transport-Security",
            Severity.MEDIUM,
            finding_id="f002",
        ),
        _finding(
            "Open redirect on checkout",
            "Redirect parameter not validated",
            Severity.HIGH,
            finding_id="f003",
        ),
        _finding(
            "Exposed .git directory",
            "The .git folder is publicly accessible",
            Severity.HIGH,
            finding_id="f004",
        ),
        _finding(
            "Weak cookie flags",
            "Session cookie missing HttpOnly flag",
            Severity.LOW,
            finding_id="f005",
        ),
    ]
    retriever = FindingRetriever(findings)
    try:
        results = retriever.retrieve("HSTS header", top_k=5)
        ids = {f.finding_id for f in results}
        assert "f002" in ids, "HSTS finding should be returned for HSTS query"
    finally:
        retriever.close()


def test_retrieve_returns_at_most_top_k():
    """retrieve() must never return more items than top_k."""
    findings = [
        _finding(
            f"Finding {i}",
            f"description {i}",
            Severity.MEDIUM,
            finding_id=f"f{i:03d}",
        )
        for i in range(20)
    ]
    retriever = FindingRetriever(findings)
    try:
        results = retriever.retrieve("description", top_k=5)
        assert len(results) <= 5
    finally:
        retriever.close()


# ---------------------------------------------------------------------------
# Fallback behaviour
# ---------------------------------------------------------------------------


def test_empty_query_returns_fallback():
    """A query that matches nothing must fall back to CRITICAL/HIGH findings."""
    findings = [
        _finding(
            "Critical auth bypass",
            "Unauthenticated access to admin",
            Severity.CRITICAL,
            finding_id="crit1",
        ),
        _finding(
            "High XSS stored",
            "Persistent XSS in comments",
            Severity.HIGH,
            finding_id="high1",
        ),
        _finding(
            "Info banner disclosure",
            "Server version in headers",
            Severity.INFO,
            finding_id="info1",
        ),
    ]
    retriever = FindingRetriever(findings)
    try:
        # Use a query that will not match any indexed content
        results = retriever.retrieve("zzzzznonexistentxxx", top_k=10)
        ids = {f.finding_id for f in results}
        assert "crit1" in ids, "CRITICAL finding must appear in fallback"
        assert "high1" in ids, "HIGH finding must appear in fallback"
        assert "info1" not in ids, "INFO finding must not be included in fallback"
    finally:
        retriever.close()


def test_fallback_capped_at_top_k():
    """Fallback must not exceed top_k even when many CRITICAL/HIGH findings exist."""
    findings = [
        _finding(
            f"Critical finding {i}",
            f"critical vuln {i}",
            Severity.CRITICAL,
            finding_id=f"c{i:03d}",
        )
        for i in range(10)
    ] + [
        _finding(
            f"High finding {i}",
            f"high vuln {i}",
            Severity.HIGH,
            finding_id=f"h{i:03d}",
        )
        for i in range(10)
    ]
    retriever = FindingRetriever(findings)
    try:
        results = retriever.retrieve("zzzzznonexistentxxx", top_k=3)
        assert len(results) <= 3, "Fallback results must be capped at top_k"
    finally:
        retriever.close()


def test_fallback_not_triggered_when_enough_fts_results():
    """Fallback must not add findings when FTS already returned >= 3 results."""
    findings = [
        _finding(
            "SQL Injection alpha",
            "injectable parameter alpha",
            Severity.MEDIUM,
            finding_id="m1",
        ),
        _finding(
            "SQL Injection beta",
            "injectable parameter beta",
            Severity.MEDIUM,
            finding_id="m2",
        ),
        _finding(
            "SQL Injection gamma",
            "injectable parameter gamma",
            Severity.MEDIUM,
            finding_id="m3",
        ),
        _finding(
            "Critical unrelated",
            "something completely different",
            Severity.CRITICAL,
            finding_id="crit_extra",
        ),
    ]
    retriever = FindingRetriever(findings)
    try:
        results = retriever.retrieve("injectable", top_k=10)
        ids = {f.finding_id for f in results}
        # The three MEDIUM findings must be found by FTS
        assert {"m1", "m2", "m3"}.issubset(ids)
        # Because FTS returned >= 3 results, the critical finding should NOT
        # have been added via fallback
        assert "crit_extra" not in ids
    finally:
        retriever.close()


# ---------------------------------------------------------------------------
# close() behaviour
# ---------------------------------------------------------------------------


def test_close_cleans_up():
    """After close(), the underlying connection should be closed
    and operations raise."""
    findings = [
        _finding(
            "XSS reflected",
            "Reflected XSS in search param",
            Severity.HIGH,
        )
    ]
    retriever = FindingRetriever(findings)
    retriever.close()

    with pytest.raises((sqlite3.ProgrammingError, sqlite3.OperationalError)):
        retriever.retrieve("XSS")


# ---------------------------------------------------------------------------
# FTS special character escaping
# ---------------------------------------------------------------------------


def test_fts_special_chars_escaped():
    """Queries containing FTS5 metacharacters must not raise an exception."""
    findings = [
        _finding(
            "Auth bypass",
            "Authentication bypass via token manipulation",
            Severity.CRITICAL,
            finding_id="a1",
        ),
        _finding(
            "Open redirect",
            "Redirect to external domain",
            Severity.HIGH,
            finding_id="a2",
        ),
    ]
    retriever = FindingRetriever(findings)
    try:
        special_queries = [
            'injection*"(){}:-',
            "OR AND NOT",
            "^~*",
            '"-bypass"',
            "token:value",
            "(nested (parens))",
            "",
        ]
        for query in special_queries:
            # Must complete without raising
            results = retriever.retrieve(query, top_k=5)
            assert isinstance(results, list), f"Expected list for query {query!r}"
    finally:
        retriever.close()


def test_fts_escape_empty_string_returns_empty_query_token():
    """_fts_escape('') must return the safe empty-match token, not raise."""
    result = FindingRetriever._fts_escape("")
    assert result == '""'


def test_fts_escape_strips_special_chars():
    """_fts_escape should remove FTS5 special characters from tokens."""
    raw = "auth*bypass"
    escaped = FindingRetriever._fts_escape(raw)
    # The '*' is stripped; the two token parts must be individually quoted
    assert "*" not in escaped
    assert '"auth' in escaped or '"bypass"' in escaped


# ---------------------------------------------------------------------------
# Edge cases
# ---------------------------------------------------------------------------


def test_empty_findings_list_returns_empty():
    """A retriever built on zero findings must return an empty list."""
    retriever = FindingRetriever([])
    try:
        results = retriever.retrieve("anything", top_k=10)
        assert results == []
    finally:
        retriever.close()


def test_retrieve_deduplicates_findings():
    """Each finding_id must appear at most once in results."""
    findings = [
        _finding(
            "Duplicate title",
            "same description injectable",
            Severity.HIGH,
            finding_id="dup1",
        ),
        _finding(
            "Another finding",
            "injectable parameter here",
            Severity.MEDIUM,
            finding_id="dup2",
        ),
    ]
    retriever = FindingRetriever(findings)
    try:
        results = retriever.retrieve("injectable", top_k=10)
        ids = [f.finding_id for f in results]
        assert len(ids) == len(set(ids)), "No finding should appear more than once"
    finally:
        retriever.close()


def test_single_finding_triggers_fallback_if_critical():
    """A single CRITICAL finding returned by FTS (< 3) does not
    re-add itself via fallback."""
    findings = [
        _finding(
            "Critical RCE",
            "Remote code execution via deserialization",
            Severity.CRITICAL,
            finding_id="rce1",
        ),
        _finding(
            "Medium info leak",
            "Information disclosure in headers",
            Severity.MEDIUM,
            finding_id="med1",
        ),
    ]
    retriever = FindingRetriever(findings)
    try:
        # Query that matches only the CRITICAL finding
        results = retriever.retrieve("deserialization", top_k=10)
        ids = [f.finding_id for f in results]
        # No duplicate entries
        assert ids.count("rce1") == 1
    finally:
        retriever.close()
