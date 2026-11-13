import argparse
import logging
import sys
from collections.abc import Callable
from pathlib import Path
from typing import Any

from pydantic import ValidationError

from haris.ai_security.options import ai_scanner_options
from haris.cli_handlers import confirm_authorisation
from haris.config.loader import load_config
from haris.core.exit_codes import EXIT_INCOMPLETE, EXIT_USAGE, exit_code
from haris.core.runner import ScanRunner
from haris.diff import load_report
from haris.llm.litellm_backend import LLMConfigError
from haris.models import ScanSession
from haris.net import NetworkPolicy
from haris.reporting import write_reports
from haris.scan_files import (
    baseline_summary,
    resolve_ignore_file,
    write_partial_session,
)
from haris.verify import VerifyMode


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


def run_scan(args: argparse.Namespace) -> int:
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
