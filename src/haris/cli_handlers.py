import argparse
import importlib
import logging
import os
import sys
from pathlib import Path

from haris.config.loader import load_config
from haris.core.decorators import all_registered
from haris.core.exit_codes import EXIT_USAGE
from haris.core.profiles import list_profiles
from haris.diff import ReportError, diff_reports, format_diff, load_report
from haris.llm.base import create_backend_from_config
from haris.llm.litellm_backend import LLMConfigError, scrub

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
