import argparse
from typing import Any

AI_SCANNERS = ("ai_security", "garak", "promptfoo")
ACTIVE_KEY = "active"
AUTHORISED_KEY = "authorised"


def active_enabled(options: dict[str, Any]) -> bool:
    """Prompts may be sent only with the active flag and an explicit authorisation."""
    return bool(options.get(ACTIVE_KEY) and options.get(AUTHORISED_KEY))


def ai_scanner_options(
    active: bool, authorised: bool, markers: list[str] | None = None
) -> dict[str, dict[str, Any]]:
    """``ScanRunner(scanner_options=...)`` for the AI scanners; empty unless active."""
    if not active:
        return {}
    shared: dict[str, Any] = {ACTIVE_KEY: True, AUTHORISED_KEY: authorised}
    options = {name: dict(shared) for name in AI_SCANNERS}
    options["ai_security"]["system_prompt_markers"] = list(markers or [])
    return options


def add_ai_arguments(parser: argparse.ArgumentParser) -> None:
    parser.add_argument(
        "--ai-active",
        action="store_true",
        help="Send prompts to AI endpoints (needs --i-have-authorization)",
    )
    parser.add_argument(
        "--ai-system-prompt-marker",
        action="append",
        metavar="TEXT",
        help="Text that proves a system prompt leak (repeatable)",
    )
