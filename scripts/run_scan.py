import argparse
import importlib
import logging
import re
import sys
from pathlib import Path
from typing import Any
from urllib.parse import urlparse

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

# Import checks and scanners to trigger @register_scanner / @register_check
import src.checks  # noqa: F401
import src.scanners  # noqa: F401
from src.config.loader import load_config
from src.core.decorators import all_registered
from src.core.profiles import PROFILES, list_profiles
from src.core.runner import ScanRunner
from src.llm.base import create_backend
from src.reporting import REPORTER_REGISTRY

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


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
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
        help="Report formats: markdown,json,html",
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
        default="0.0.0.0",
        help="Web UI bind address (with --web)",
    )
    parser.add_argument(
        "--port",
        type=int,
        default=8000,
        help="Web UI port (with --web)",
    )

    parser.add_argument(
        "--llm-enrich",
        action="store_true",
        help="Enable LLM-powered finding enrichment during scan",
    )
    parser.add_argument(
        "--llm-backend",
        default=None,
        help="LLM backend for enrichment (anthropic, openai, ollama)",
    )

    subparsers = parser.add_subparsers(dest="subcommand")

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
        default="openai",
        help="LLM backend (openai, anthropic, ollama)",
    )
    ask_parser.add_argument("--model", default=None, help="Model name override")

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
    summarize_parser.add_argument("--backend", default="openai", help="LLM backend")
    summarize_parser.add_argument("--model", default=None, help="Model name override")

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
    remediate_parser.add_argument("--backend", default="openai", help="LLM backend")
    remediate_parser.add_argument("--model", default=None, help="Model name override")

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
    tests_parser.add_argument("--backend", default="openai", help="LLM backend")
    tests_parser.add_argument("--model", default=None, help="Model name override")

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


def _create_backend(args: argparse.Namespace):
    kwargs = {}
    if hasattr(args, "model") and args.model:
        kwargs["model"] = args.model
    return create_backend(args.backend, **kwargs)  # type: ignore[return-value]


def handle_update_templates(args: argparse.Namespace) -> int:
    from src.templates.manager import TemplateManager
    from src.templates.report import TemplateUpdateReporter

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


def handle_llm_command(args: argparse.Namespace) -> int:
    from src.llm.qa import ReportQA

    if not args.llm_action:
        print("Usage: HARIS llm {ask|summarize|remediate|test-cases}")
        return 1

    backend = _create_backend(args)

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
        print(f"LLM error: {exc}")
        return 1


def _handle_non_scan_actions(args: argparse.Namespace) -> int | None:
    if args.subcommand == "update-templates":
        return handle_update_templates(args)
    if args.subcommand == "llm":
        return handle_llm_command(args)

    if args.list_profiles:
        print("Available scan profiles:\n")
        show_profiles()
        return 0

    if args.list_scanners:
        print("Available scanners and checks:\n")
        show_scanners()
        return 0

    if args.web:
        from src.web.app import app

        uvicorn = importlib.import_module("uvicorn")

        print("Starting HARIS dashboard...")
        uvicorn.run(app, host=args.host, port=args.port)
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


def _domain_slug(url: str) -> str:
    """Extract a filesystem-safe domain slug from a URL."""
    hostname = urlparse(url).hostname or "unknown"
    return re.sub(r"[^a-zA-Z0-9._-]", "_", hostname)


def _write_reports(session: Any, config: Any) -> None:
    output_dir = Path(config.output_dir)
    output_dir.mkdir(parents=True, exist_ok=True)

    domain = _domain_slug(session.target.base_url)

    for fmt in config.report_formats:
        reporter_cls = REPORTER_REGISTRY.get(fmt)
        if reporter_cls is None:
            logging.warning("Unknown report format: %s", fmt)
            continue
        reporter = reporter_cls()
        filename = f"report_{domain}_{session.session_id}{reporter.file_extension}"
        out_path = reporter.write(session, output_dir / filename)
        print(f"Report: {out_path}")


def _save_session_to_db(session: Any) -> None:
    try:
        from src.db.store import ScanStore

        store = ScanStore()
        store.save_session(session)
        print(f"Database: saved session {session.session_id}")
    except Exception as exc:
        logging.warning("Could not save to database: %s", exc)


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

    non_scan_result = _handle_non_scan_actions(args)
    if non_scan_result is not None:
        return non_scan_result

    overrides = _build_overrides(args)
    config = load_config(config_path=args.config, overrides=overrides)

    logging.basicConfig(
        level=getattr(logging, config.log_level, logging.INFO),
        format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
        datefmt="%H:%M:%S",
    )

    if not confirm_authorisation(config.target.base_url, skip=args.yes):
        print("Aborted. You must confirm authorisation to proceed.")
        return 1

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
        )
        session = runner.run()
    except RuntimeError as exc:
        print(f"Error: {exc}")
        return 1

    _write_reports(session, config)
    _save_session_to_db(session)
    _print_session_summary(session)

    return 0


if __name__ == "__main__":
    sys.exit(main())
