import os
import re
from pathlib import Path
from typing import Any
from urllib.parse import urlsplit

import yaml

from ..models import ScanContext, Target

CONTEXT_NAME = "haris"
TEMPLATE_ID = "traditional-json"
REPORT_FILE = "zap-report.json"
PLAN_NAME = "plan.yaml"
HOME_DIR = "zap-home"
PLAN_MODE = 0o600
HOST_LABEL = r"(?:[A-Za-z0-9-]+\.)*"


def context_url(target: Target) -> str:
    """Drop :80 and :443; ZAP treats those URLs as a different context."""
    parts = urlsplit(target.base_url)
    host = parts.hostname or ""
    if ":" in host:
        host = f"[{host}]"
    port = "" if parts.port in (None, 80, 443) else f":{parts.port}"
    return f"{parts.scheme}://{host}{port}{parts.path}"


def include_regex(domain: str) -> str:
    """Host equals the domain or is a subdomain, matching Scope.is_url_in_scope."""
    return rf"^https?://{HOST_LABEL}{re.escape(domain)}(?::\d+)?(?:[/?#]|$)"


def exclude_regex(pattern: str) -> str:
    """HARIS searches the path; ZAP searches the URL. Escape the path as a literal."""
    return rf"^https?://[^/?#]+(?::\d+)?[^?#]*{re.escape(pattern)}"


def delay_ms(options: dict[str, Any], context: ScanContext | None) -> int:
    rate = context.tool_rate_rps if context is not None else 0
    if rate > 0:
        return max(1, int(1000 / rate))
    return int(options["delay_ms"])


def replacer_rules(target: Target) -> list[dict[str, Any]]:
    return [
        {
            "description": "haris-auth",
            "matchType": "req_header",
            "matchString": name,
            "matchRegex": False,
            "replacementString": value,
        }
        for name, value in target.auth.as_headers().items()
    ]


def build_plan(
    target: Target, work: Path, context: ScanContext | None, options: dict[str, Any]
) -> dict[str, Any]:
    url = context_url(target)
    threads = int(options["threads"])
    jobs: list[dict[str, Any]] = []
    rules = replacer_rules(target)
    if rules:
        jobs.append(
            {
                "type": "replacer",
                "parameters": {"deleteAllRules": False},
                "rules": rules,
            }
        )
    jobs.extend(
        [
            {
                "type": "spider",
                "parameters": {
                    "context": CONTEXT_NAME,
                    "url": url,
                    "maxDuration": int(options["spider_minutes"]),
                    "threadCount": threads,
                },
            },
            {
                "type": "passiveScan-wait",
                "parameters": {"maxDuration": int(options["passive_minutes"])},
            },
            {
                "type": "activeScan",
                "parameters": {
                    "context": CONTEXT_NAME,
                    "maxScanDurationInMins": int(options["active_minutes"]),
                    "delayInMs": delay_ms(options, context),
                    "threadPerHost": threads,
                },
            },
            {
                "type": "report",
                "parameters": {
                    "template": TEMPLATE_ID,
                    "reportDir": str(work),
                    "reportFile": REPORT_FILE,
                    "displayReport": False,
                },
            },
        ]
    )
    return {
        "env": {
            "contexts": [
                {
                    "name": CONTEXT_NAME,
                    "urls": [url],
                    "includePaths": [
                        include_regex(domain) for domain in target.scope.allowed_domains
                    ],
                    "excludePaths": [
                        exclude_regex(pattern)
                        for pattern in target.scope.excluded_paths
                    ],
                }
            ],
            "parameters": {
                "failOnError": False,
                "failOnWarning": False,
                "continueOnFailure": True,
                "progressToStdout": False,
            },
        },
        "jobs": jobs,
    }


def write_plan(work: Path, plan: dict[str, Any]) -> Path:
    path = work / PLAN_NAME
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, PLAN_MODE)
    with os.fdopen(fd, "w", encoding="utf-8") as handle:
        yaml.safe_dump(plan, handle, sort_keys=False)
    return path


def command(launcher: str, plan_path: Path, home: Path, extra: list[str]) -> list[str]:
    # Auth stays in the plan. -cmd -autorun is the documented invocation.
    return [
        launcher,
        "-cmd",
        "-autorun",
        str(plan_path),
        "-dir",
        str(home),
        "-silent",
        *extra,
    ]
