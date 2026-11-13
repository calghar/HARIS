import argparse
import sys
from typing import NoReturn

from haris.ai_security.options import add_ai_arguments
from haris.core.engine import DEFAULT_PARALLEL
from haris.core.exit_codes import EXIT_USAGE
from haris.core.profiles import PROFILES
from haris.ignore import DEFAULT_IGNORE_FILE
from haris.models import Severity
from haris.reporting import REPORTER_REGISTRY
from haris.verify import DEFAULT_VERIFY_MODE, VerifyMode


class _UsageParser(argparse.ArgumentParser):
    """Exits 3 (not argparse's 2) on usage errors; 2 means an incomplete scan."""

    def error(self, message: str) -> NoReturn:
        self.print_usage(sys.stderr)
        self.exit(EXIT_USAGE, f"{self.prog}: error: {message}\n")


def _severity(value: str) -> Severity:
    try:
        return Severity(value.lower())
    except ValueError:
        choices = ", ".join(s.value for s in Severity)
        raise argparse.ArgumentTypeError(
            f"invalid severity {value!r} (choose from {choices})"
        ) from None


def _positive_int(value: str) -> int:
    if not value.isdigit() or int(value) < 1:
        raise argparse.ArgumentTypeError(f"{value!r} is not a positive integer")
    return int(value)


def build_parser() -> argparse.ArgumentParser:
    parser = _UsageParser(
        description="HARIS: black-box web application security auditor",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=(
            "Examples:\n"
            "  %(prog)s --url https://example.com --profile quick --yes\n"
            "  %(prog)s --config config/my_target.yaml\n"
            "  %(prog)s --url https://example.com --scanners header_checks,tls_checks\n"
            "  %(prog)s --web\n"
            "  %(prog)s --list-profiles\n"
            "  %(prog)s llm ask --scan-id abc123 --question 'Top 3 risks'\n"
        ),
    )
    parser.add_argument("--url", help="Target URL to scan")
    parser.add_argument("--config", default=None, help="Path to YAML config file")
    parser.add_argument(
        "--profile",
        choices=list(PROFILES.keys()),
        default=None,
        help="Scan profile (see --list-profiles)",
    )
    parser.add_argument("--scanners", default=None, help="Comma-separated scanner list")
    parser.add_argument("--output", default=None, help="Output directory for reports")
    parser.add_argument(
        "--formats",
        default=None,
        help="Report formats: " + ",".join(REPORTER_REGISTRY),
    )
    parser.add_argument(
        "--log-level",
        choices=["DEBUG", "INFO", "WARNING", "ERROR"],
        default=None,
    )
    parser.add_argument("--yes", action="store_true", help="Skip authorisation prompt")
    parser.add_argument(
        "--list-profiles",
        action="store_true",
        help="Show available profiles and exit",
    )
    parser.add_argument(
        "--list-scanners",
        action="store_true",
        help="Show available scanners and exit",
    )
    parser.add_argument(
        "--web",
        action="store_true",
        help="Start the web dashboard instead of CLI scan",
    )
    parser.add_argument(
        "--host",
        default="127.0.0.1",
        help="Web UI bind address (with --web)",
    )
    parser.add_argument(
        "--port",
        type=int,
        default=8000,
        help="Web UI port (with --web)",
    )
    parser.add_argument(
        "--proxy-headers",
        action="store_true",
        help="Trust X-Forwarded-* headers from a reverse proxy (with --web)",
    )

    parser.add_argument(
        "--llm-enrich",
        action="store_true",
        help="Enable LLM-powered finding enrichment during scan",
    )
    parser.add_argument(
        "--llm-backend",
        default=None,
        help="LLM backend for enrichment (litellm; the model comes from llm.model)",
    )
    parser.add_argument(
        "--fail-on",
        type=_severity,
        default=None,
        metavar="SEVERITY",
        help="Exit 1 when a finding at or above this severity remains",
    )
    parser.add_argument(
        "--baseline",
        default=None,
        metavar="REPORT.json",
        help="Compare the scan with an earlier JSON report",
    )
    parser.add_argument(
        "--ignore-file",
        default=None,
        metavar="PATH",
        help=f"Suppression file (default: ./{DEFAULT_IGNORE_FILE} when present)",
    )
    parser.add_argument(
        "--allow-private",
        action="store_true",
        help="Allow targets on private, loopback and link-local addresses",
    )
    parser.add_argument(
        "--parallel",
        type=_positive_int,
        default=DEFAULT_PARALLEL,
        help="Scanners to run concurrently (default: %(default)s)",
    )

    add_ai_arguments(parser)

    parser.add_argument(
        "--verify",
        choices=[m.value for m in VerifyMode],
        default=DEFAULT_VERIFY_MODE.value,
        help="Verification: off, replay (default) or llm (replay plus LLM verdict)",
    )
    parser.add_argument(
        "--agent", action="store_true", help="Opt-in sandboxed validator"
    )
    parser.add_argument(
        "--i-have-authorization",
        action="store_true",
        help="Confirm written authorisation; required with --agent and --ai-active",
    )
    parser.add_argument(
        "--agent-allow-unsafe-methods",
        action="store_true",
        help="Allow POST replay of a finding that was observed as POST",
    )

    subparsers = parser.add_subparsers(dest="subcommand")

    diff_parser = subparsers.add_parser(
        "diff",
        help="Compare two JSON reports (new, fixed, not_retested, unchanged)",
    )
    diff_parser.add_argument("old", help="Earlier JSON report")
    diff_parser.add_argument("new", help="Later JSON report")

    bench_sub = subparsers.add_parser("bench", help="Benchmark tools").add_subparsers(
        dest="bench_action", required=True
    )
    bench_score = bench_sub.add_parser(
        "score", help="Score HARIS JSON reports against ground truth"
    )
    bench_score.add_argument("report", help="Report file, or directory of reports")
    bench_score.add_argument("ground_truth", help="Ground-truth YAML")
    bench_score.add_argument("--baseline", help="Baseline report file or directory")
    bench_score.add_argument(
        "--out", help="Output directory (default: <report dir>/score)"
    )

    tmpl_parser = subparsers.add_parser(
        "update-templates",
        help="Update scanner templates from upstream",
    )
    tmpl_parser.add_argument(
        "--scanner",
        default=None,
        help="Only update this scanner's templates",
    )
    tmpl_parser.add_argument(
        "--force",
        action="store_true",
        help="Force re-download",
    )
    tmpl_parser.add_argument(
        "--list",
        action="store_true",
        dest="list_templates",
        help="Show current template status and exit",
    )
    tmpl_parser.add_argument("--config", default=None, help="Config file")

    llm_parser = subparsers.add_parser("llm", help="LLM-powered report analysis")
    llm_sub = llm_parser.add_subparsers(dest="llm_action")

    ask_parser = llm_sub.add_parser("ask", help="Ask a question about a scan")
    ask_parser.add_argument(
        "--scan-id",
        required=True,
        help="Scan ID or report file path",
    )
    ask_parser.add_argument("--question", required=True, help="Question to ask")
    ask_parser.add_argument(
        "--backend",
        default="litellm",
        help="LLM backend (litellm; the model comes from --model or llm.model)",
    )
    ask_parser.add_argument(
        "--model", default=None, help="LiteLLM model string; overrides llm.model"
    )

    summarize_parser = llm_sub.add_parser("summarize", help="Summarize a scan report")
    summarize_parser.add_argument(
        "--scan-id",
        required=True,
        help="Scan ID or report file path",
    )
    summarize_parser.add_argument(
        "--audience",
        default="executive",
        choices=["executive", "technical", "developer"],
    )
    summarize_parser.add_argument("--backend", default="litellm", help="LLM backend")
    summarize_parser.add_argument(
        "--model", default=None, help="LiteLLM model string; overrides llm.model"
    )

    remediate_parser = llm_sub.add_parser(
        "remediate",
        help="Generate a remediation plan",
    )
    remediate_parser.add_argument(
        "--scan-id",
        required=True,
        help="Scan ID or report file path",
    )
    remediate_parser.add_argument(
        "--format",
        default="markdown",
        choices=["markdown", "jira", "email"],
    )
    remediate_parser.add_argument("--backend", default="litellm", help="LLM backend")
    remediate_parser.add_argument(
        "--model", default=None, help="LiteLLM model string; overrides llm.model"
    )

    tests_parser = llm_sub.add_parser("test-cases", help="Generate security test cases")
    tests_parser.add_argument(
        "--scan-id",
        required=True,
        help="Scan ID or report file path",
    )
    tests_parser.add_argument(
        "--framework",
        default="generic",
        help="Target test framework",
    )
    tests_parser.add_argument("--backend", default="litellm", help="LLM backend")
    tests_parser.add_argument(
        "--model", default=None, help="LiteLLM model string; overrides llm.model"
    )

    return parser
