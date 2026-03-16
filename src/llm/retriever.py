"""Full-text search over findings for selective context retrieval.

Uses SQLite FTS5 (built into Python's sqlite3) for BM25-ranked
retrieval. No external dependencies required.
"""

import re
import sqlite3

from ..models import Finding


# Characters that have special meaning in FTS5 query syntax
_FTS5_SPECIAL = re.compile(r'[*"(){}:\-^~]')


class FindingRetriever:
    """BM25-ranked full-text search over scan findings.

    Usage::

        retriever = FindingRetriever(session.all_findings)
        relevant = retriever.retrieve("authentication bypass", top_k=10)
    """

    def __init__(self, findings: list[Finding]) -> None:
        self._findings = {f.finding_id: f for f in findings}
        self._conn = sqlite3.connect(":memory:")
        self._conn.row_factory = sqlite3.Row
        self._build_index(findings)

    def _build_index(self, findings: list[Finding]) -> None:
        self._conn.execute(
            "CREATE VIRTUAL TABLE finding_fts USING fts5("
            "finding_id, title, description, evidence, "
            "remediation, owasp_category, tags, scanner, url, "
            "tokenize='porter unicode61'"
            ")"
        )
        for f in findings:
            self._conn.execute(
                "INSERT INTO finding_fts VALUES "
                "(?, ?, ?, ?, ?, ?, ?, ?, ?)",
                (
                    f.finding_id,
                    f.title,
                    f.description,
                    f.evidence,
                    f.remediation,
                    f.owasp_category or "",
                    " ".join(f.tags),
                    f.scanner,
                    f.url,
                ),
            )

    @staticmethod
    def _fts_escape(query: str) -> str:
        """Escape special FTS5 characters and format as OR query."""
        cleaned = _FTS5_SPECIAL.sub(" ", query)
        tokens = cleaned.split()
        if not tokens:
            return '""'
        # Join tokens with OR for broader matching
        return " OR ".join(f'"{t}"' for t in tokens if t)

    def retrieve(
        self, query: str, top_k: int = 10
    ) -> list[Finding]:
        """Return top-k most relevant findings for a query.

        Falls back to including all CRITICAL/HIGH findings if
        FTS returns fewer than 3 results.
        """
        escaped = self._fts_escape(query)
        try:
            rows = self._conn.execute(
                "SELECT finding_id, rank "
                "FROM finding_fts "
                "WHERE finding_fts MATCH ? "
                "ORDER BY rank "
                "LIMIT ?",
                (escaped, top_k),
            ).fetchall()
        except sqlite3.OperationalError:
            # Malformed query — return empty, let fallback handle it
            rows = []

        result_ids = {r["finding_id"] for r in rows}
        results = [
            self._findings[fid]
            for fid in result_ids
            if fid in self._findings
        ]

        # Fallback: if too few results, add CRITICAL/HIGH findings
        if len(results) < 3:
            for f in self._findings.values():
                if len(results) >= top_k:
                    break
                if f.finding_id not in result_ids and f.severity.value in (
                    "critical",
                    "high",
                ):
                    results.append(f)
                    result_ids.add(f.finding_id)

        return results

    def close(self) -> None:
        self._conn.close()
