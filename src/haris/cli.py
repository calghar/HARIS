import argparse
import importlib
import logging
import os
import sys
from collections.abc import Callable
from pathlib import Path
from typing import Any, NoReturn

from pydantic import ValidationError

from haris.ai_security.options import add_ai_arguments, ai_scanner_options
from haris.config.loader import load_config
from haris.core.decorators import all_registered
from haris.core.engine import DEFAULT_PARALLEL
from haris.core.exit_codes import EXIT_INCOMPLETE, EXIT_USAGE, exit_code
from haris.core.profiles import PROFILES, list_profiles
from haris.core.runner import ScanRunner
from haris.diff import ReportError, diff_reports, format_diff, load_report
from haris.ignore import DEFAULT_IGNORE_FILE
from haris.llm.base import create_backend_from_config
from haris.llm.litellm_backend import LLMConfigError, scrub
from haris.models import ScanSession, Severity
from haris.net import NetworkPolicy
from haris.reporting import REPORTER_REGISTRY, write_reports
from haris.scan_files import (
    baseline_summary,
    resolve_ignore_file,
    write_partial_session,
)
from haris.verify import DEFAULT_VERIFY_MODE, VerifyMode

LEGAL_BANNER = """
============================================================
  HARIS — Black-Box Web Security Audit Framework
============================================================
  WARNING: This tool performs active security testing.
  Only use against systems you are AUTHORISED to test.
  Unauthorised scanning may violate laws and regulations.
  See LEGAL_NOTICE.md for details.
============================================================
"""


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


def confirm_authorisation(target_url: str, skip: bool = False) -> bool:
    if skip:
        return True
    print(LEGAL_BANNER)
    print(f"  Target: {target_url}\n")
    try:
        answer = input("Do you confirm you are AUTHORISED to test this target? [y/N] ")
    except (EOFError, KeyboardInterrupt):
        print()
        return False
    return answer.strip().lower() in ("y", "yes")


def show_profiles() -> None:
    for p in list_profiles():
        print(f"  {p.name:<14} {p.display_name}")
        print(f"  {'':14} {p.description}")
        print(f"  {'':14} Scanners: {', '.join(p.scanners)}")
        print(f"  {'':14} Duration: ~{p.estimated_duration}")
        print()


def show_scanners() -> None:
    registered = all_registered()
    for name, cls in sorted(registered.items()):
        desc = getattr(cls, "description", "")
        print(f"  {name:<20} {desc}")


def _resolve_report_path(scan_id: str) -> Path:
    path = Path(scan_id)
    if path.exists() and path.suffix == ".json":
        return path

    reports_dir = Path("./reports")
    for candidate in reports_dir.glob(f"report_{scan_id}*.json"):
        return candidate

    exact = reports_dir / f"report_{scan_id}.json"
    if exact.exists():
        return exact

    print(f"Error: Could not find report for scan '{scan_id}'")
    print(f"Looked in: {reports_dir}")
    sys.exit(1)


def handle_update_templates(args: argparse.Namespace) -> int:
    from haris.templates.manager import TemplateManager
    from haris.templates.report import TemplateUpdateReporter

    config = load_config(config_path=getattr(args, "config", None))

    logging.basicConfig(
        level=getattr(logging, config.log_level, logging.INFO),
        format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
        datefmt="%H:%M:%S",
    )

    mgr = TemplateManager(
        base_dir=config.template_dir,
        sources=config.template_sources,
    )
    reporter = TemplateUpdateReporter()

    if getattr(args, "list_templates", False):
        metadata = mgr.list_sources()
        print(reporter.format_summary(metadata))
        return 0

    results = mgr.update_templates(
        scanner_name=args.scanner,
        force=args.force,
    )
    print(reporter.format_cli(results))
    return 0 if all(r.success for r in results) else 1


def handle_diff(args: argparse.Namespace) -> int:
    try:
        old = load_report(Path(args.old))
        new = load_report(Path(args.new))
    except ReportError as exc:
        print(f"Error: {exc}", file=sys.stderr)
        return EXIT_USAGE
    print(format_diff(diff_reports(old, new)))
    return 0


def handle_bench(args: argparse.Namespace) -> int:
    from haris.bench.__main__ import main as bench_main

    argv = ["score", args.report, args.ground_truth]
    for flag in ("baseline", "out"):
        if getattr(args, flag):
            argv += [f"--{flag}", getattr(args, flag)]
    try:
        return bench_main(argv)
    except (OSError, ValueError) as exc:
        print(f"Error: {exc}", file=sys.stderr)
        return EXIT_USAGE


def handle_llm_command(args: argparse.Namespace) -> int:
    from haris.llm.qa import ReportQA

    if not args.llm_action:
        print("Usage: HARIS llm {ask|summarize|remediate|test-cases}")
        return 1

    llm = load_config().llm
    try:
        backend = create_backend_from_config(llm, args.backend, args.model or "")
    except LLMConfigError as exc:
        print(f"Error: {exc}", file=sys.stderr)
        return EXIT_USAGE

    try:
        qa, session = ReportQA.from_db(args.scan_id, backend)
    except Exception:
        report_path = _resolve_report_path(args.scan_id)
        try:
            qa, session = ReportQA.from_json_file(report_path, backend)
        except Exception as exc:
            print(f"Error loading report: {exc}")
            return 1

    try:
        if args.llm_action == "ask":
            response = qa.ask(session, args.question)
        elif args.llm_action == "summarize":
            response = qa.summarize(session, audience=args.audience)
        elif args.llm_action == "remediate":
            response = qa.remediation_plan(session, format=args.format)
        elif args.llm_action == "test-cases":
            response = qa.generate_test_cases(session, framework=args.framework)
        else:
            print(f"Unknown llm action: {args.llm_action}")
            return 1

        print(response.text)
        if response.usage:
            print(f"\n---\nTokens used: {response.token_count}")
        return 0

    except Exception as exc:
        print(f"LLM error: {scrub(str(exc), os.environ.get(llm.api_key_env))}")
        return 1


def _handle_non_scan_actions(args: argparse.Namespace) -> int | None:
    if args.subcommand == "update-templates":
        return handle_update_templates(args)
    if args.subcommand == "llm":
        return handle_llm_command(args)
    if args.subcommand == "diff":
        return handle_diff(args)
    if args.subcommand == "bench":
        return handle_bench(args)

    if args.list_profiles:
        print("Available scan profiles:\n")
        show_profiles()
        return 0

    if args.list_scanners:
        print("Available scanners and checks:\n")
        show_scanners()
        return 0

    if args.web:
        from haris.web.app import create_app

        uvicorn = importlib.import_module("uvicorn")

        print("Starting HARIS dashboard...")
        uvicorn.run(
            create_app(),
            host=args.host,
            port=args.port,
            proxy_headers=args.proxy_headers,
        )
        return 0

    return None


def _build_overrides(args: argparse.Namespace) -> dict[str, Any]:
    overrides: dict[str, Any] = {}
    if args.url:
        overrides.setdefault("target", {})["url"] = args.url
    if args.profile:
        overrides["profile"] = args.profile
    if args.output:
        overrides["output_dir"] = args.output
    if args.formats:
        overrides["report_formats"] = args.formats.split(",")
    if args.log_level:
        overrides["log_level"] = args.log_level
    return overrides


def _write_reports(session: Any, config: Any, baseline: Any = None) -> None:
    for path in write_reports(
        session,
        Path(config.output_dir),
        config.report_formats,
        baseline,
    ):
        print(f"Report: {path}")


def _save_session_to_db(session: Any, *, quiet: bool = False) -> None:
    try:
        from haris.db.store import ScanStore

        store = ScanStore()
        store.save_session(session)
        if not quiet:
            print(f"Database: saved session {session.session_id}")
    except Exception as exc:
        logging.warning("Could not save to database: %s", exc)


def _checkpoint(output_dir: str) -> Callable[[ScanSession], None]:
    """Persist the session after each scanner so a crash keeps partial results."""

    def save(session: ScanSession) -> None:
        write_partial_session(session, Path(output_dir))
        _save_session_to_db(session, quiet=True)

    return save


def _print_session_summary(session: Any) -> None:
    summary = session.summary()
    print(f"\nRisk posture: {session.risk_posture.value.upper()}")
    print(f"Total findings: {summary['total_findings']}")
    for sev, count in summary["by_severity"].items():
        if count > 0:
            print(f"  {sev}: {count}")

    if session.remediation_steps:
        print(f"\nRemediation: {len(session.remediation_steps)} steps")
        for i, step in enumerate(session.remediation_steps[:5], 1):
            print(f"  {i}. [{step.effort.value}] {step.title}")
        if len(session.remediation_steps) > 5:
            remaining = len(session.remediation_steps) - 5
            print(f"  ... and {remaining} more (see full report)")

    if session.errors:
        print(f"\n{len(session.errors)} error(s):")
        for err in session.errors[:5]:
            print(f"  - {err}")


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)

    from haris.agent.policy import bind_cli

    refused = bind_cli(args)
    if refused is not None:
        print("Agent mode requires --i-have-authorization.", file=sys.stderr)
        return refused

    non_scan_result = _handle_non_scan_actions(args)
    if non_scan_result is not None:
        return non_scan_result

    if args.ai_active and not args.i_have_authorization:
        print("Error: --ai-active requires --i-have-authorization.", file=sys.stderr)
        return EXIT_USAGE

    try:
        config = load_config(config_path=args.config, overrides=_build_overrides(args))
        ignore = resolve_ignore_file(args.ignore_file)
        baseline = load_report(Path(args.baseline)) if args.baseline else None
    except (ValueError, OSError, ValidationError) as exc:
        print(f"Error: {exc}", file=sys.stderr)
        return EXIT_USAGE

    logging.basicConfig(
        level=getattr(logging, config.log_level, logging.INFO),
        format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
        datefmt="%H:%M:%S",
    )

    if not confirm_authorisation(config.target.base_url, skip=args.yes):
        print("Aborted. You must confirm authorisation to proceed.")
        return EXIT_USAGE

    scanner_names = args.scanners.split(",") if args.scanners else None

    print(f"Scanning {config.target.base_url}")
    print(f"Profile: {config.profile}")
    print()

    try:
        runner = ScanRunner(
            target=config.target,
            profile_name=config.profile,
            config=config,
            scanner_names=scanner_names,
            llm_enrich=args.llm_enrich,
            llm_backend_name=args.llm_backend,
            parallel=args.parallel,
            verify=VerifyMode(args.verify),
            network_policy=NetworkPolicy(allow_private=args.allow_private),
            ignore=ignore,
            checkpoint=_checkpoint(config.output_dir),
            scanner_options=ai_scanner_options(
                args.ai_active, args.i_have_authorization, args.ai_system_prompt_marker
            ),
        )
        session = runner.run()
    except (RuntimeError, LLMConfigError) as exc:
        print(f"Error: {exc}")
        return EXIT_USAGE
    except KeyboardInterrupt:
        print("\nCancelled.")
        return EXIT_INCOMPLETE

    _write_reports(session, config, baseline)
    _save_session_to_db(session)
    _print_session_summary(session)
    if baseline is not None:
        print("\nChanges since baseline:")
        print(baseline_summary(session, baseline))

    return exit_code(session, args.fail_on)


if __name__ == "__main__":
    sys.exit(main())
