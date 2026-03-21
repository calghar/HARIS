"""HTML report generator.

Wraps the Markdown report in a self-contained HTML page with minimal
styling for easy viewing in a browser.
"""

import html

from ..models import ScanSession, Severity
from .base import BaseReporter
from .markdown_report import MarkdownReporter


class HTMLReporter(BaseReporter):
    """Generates a self-contained HTML security report.

    Uses the Markdown reporter internally and wraps the output in HTML.
    If the ``markdown`` library is available, it converts Markdown to
    HTML; otherwise it wraps the raw text in ``<pre>`` tags.
    """

    format_name = "html"
    file_extension = ".html"

    def generate(self, session: ScanSession) -> str:
        md_content = MarkdownReporter().generate(session)
        body_html = self._md_to_html(md_content)
        severity_summary = self._severity_bar(session)

        return f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>Security Audit Report - {html.escape(session.target.base_url)}</title>
<style>
  :root {{
    --bg: #f8f9fa; --fg: #212529; --accent: #0d6efd;
    --critical: #dc3545; --high: #fd7e14; --medium: #ffc107;
    --low: #198754; --info: #0dcaf0;
  }}
  body {{
    font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto,
                 "Helvetica Neue", Arial, sans-serif;
    line-height: 1.6; color: var(--fg); background: var(--bg);
    max-width: 960px; margin: 2rem auto; padding: 0 1rem;
  }}
  h1 {{ border-bottom: 3px solid var(--accent); padding-bottom: .5rem; }}
  h2 {{ margin-top: 2rem; color: var(--accent); }}
  h3 {{ margin-top: 1.5rem; }}
  table {{
    border-collapse: collapse; width: 100%; margin: 1rem 0;
  }}
  th, td {{
    border: 1px solid #dee2e6; padding: .5rem .75rem; text-align: left;
  }}
  th {{ background: #e9ecef; }}
  code, pre {{
    background: #e9ecef; padding: .15rem .3rem; border-radius: 3px;
    font-size: .9em;
  }}
  pre {{
    padding: 1rem; overflow-x: auto; white-space: pre-wrap;
    word-wrap: break-word;
  }}
  .severity-bar {{
    display: flex; height: 24px; border-radius: 4px; overflow: hidden;
    margin: 1rem 0;
  }}
  .severity-bar span {{
    display: inline-flex; align-items: center; justify-content: center;
    color: #fff; font-size: .75rem; font-weight: 600;
  }}
  blockquote {{
    border-left: 4px solid var(--accent); margin: 1rem 0;
    padding: .5rem 1rem; background: #fff;
  }}
  hr {{ border: none; border-top: 1px solid #dee2e6; margin: 2rem 0; }}
</style>
</head>
<body>
{severity_summary}
{body_html}
</body>
</html>"""

    def _md_to_html(self, md_text: str) -> str:
        """Convert Markdown to HTML, with graceful fallback."""
        try:
            import markdown  # type: ignore[import-untyped]

            result: str = markdown.markdown(
                md_text,
                extensions=["tables", "fenced_code"],
            )
            return result
        except ImportError:
            # Fallback: wrap in <pre> with basic escaping
            return f"<pre>{html.escape(md_text)}</pre>"

    def _severity_bar(self, session: ScanSession) -> str:
        """Generate a coloured severity distribution bar."""
        by_sev = session.findings_by_severity
        total = len(session.all_findings) or 1
        colors = {
            Severity.CRITICAL: "var(--critical)",
            Severity.HIGH: "var(--high)",
            Severity.MEDIUM: "var(--medium)",
            Severity.LOW: "var(--low)",
            Severity.INFO: "var(--info)",
        }

        spans = []
        for sev in Severity:
            count = len(by_sev[sev])
            if count == 0:
                continue
            pct = (count / total) * 100
            spans.append(
                f'<span style="width:{pct:.1f}%;background:{colors[sev]}">'
                f"{sev.value[0].upper()}:{count}</span>"
            )

        if not spans:
            return ""

        return f'<div class="severity-bar">{"".join(spans)}</div>'
