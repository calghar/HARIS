import math
from collections.abc import Iterable, Mapping, Sequence
from typing import Any

from .nuclei_results import (
    BASELINE_TEMPLATE_DIRS,
    EXCLUDED_TEMPLATE_IDS,
    TECH_TAG_MAP,
    TECH_WORKFLOW_MAP,
)

EXCLUDED_SEVERITY = "info"


def map_technologies(technologies: Iterable[str]) -> tuple[list[str], list[str]]:
    """Tags and workflow paths the technology maps give; workflows may repeat."""
    tags: list[str] = []
    workflows: list[str] = []
    for technology in technologies:
        lowered = technology.lower()
        for key, tag_list in TECH_TAG_MAP.items():
            if key in lowered:
                tags.extend(tag_list)
        workflows.extend(
            path for key, path in TECH_WORKFLOW_MAP.items() if key in lowered
        )
    return list(dict.fromkeys(tags)), workflows


def build_argv(
    options: Mapping[str, Any],
    base_url: str,
    *,
    proxy: str,
    rate_rps: float,
    headers: Mapping[str, str],
    extra_args: Sequence[str],
    excluded_types: Sequence[str],
    template_dirs: Sequence[str] | None = None,
    extra_tags: Sequence[str] | None = None,
    workflows: Sequence[str] | None = None,
    exclude_templates: Sequence[str] | None = None,
    automatic: bool = False,
    url_file: str | None = None,
) -> list[str]:
    """Build the nuclei argv."""
    cmd = [
        "nuclei",
        "-jsonl",
        "-or",
        "-ot",
        "-duc",
        "-silent",
        "-no-color",
        "-system-resolvers",
        "-tls-impersonate",
        "-fhr",
        "-retries",
        str(options["retries"]),
        "-mhe",
        str(options["max_host_errors"]),
        "-c",
        str(options["concurrency"]),
        "-bs",
        str(options["bulk_size"]),
        "-timeout",
        str(options.get("timeout_per_request", 30)),
    ]

    if proxy:
        cmd.extend(["-proxy", proxy])
    if rate_rps <= 0:
        cmd.extend(["-rate-limit", str(options["rate_limit"])])

    if excluded_types:
        cmd.extend(["-ept", ",".join(excluded_types)])
    if EXCLUDED_TEMPLATE_IDS:
        cmd.extend(["-eid", ",".join(sorted(EXCLUDED_TEMPLATE_IDS))])

    if not options.get("enable_interactsh"):
        cmd.append("-no-interactsh")

    if url_file:
        cmd.extend(["-list", url_file])
    else:
        cmd.extend(["-u", base_url])

    has_template_selection = automatic
    effective_dirs = template_dirs if template_dirs is not None else []
    user_template_dirs = options.get("template_dirs", [])

    if user_template_dirs:
        for tdir in user_template_dirs:
            cmd.extend(["-t", tdir])
            has_template_selection = True
    else:
        for tdir in effective_dirs:
            cmd.extend(["-t", tdir])
            has_template_selection = True

        if not effective_dirs:
            for template_path in options.get("templates", []):
                cmd.extend(["-t", template_path])
                has_template_selection = True

    for workflow_path in workflows or []:
        cmd.extend(["-w", workflow_path])
        has_template_selection = True

    all_tags: list[str] = list(options.get("tags", []))
    seen = {t.lower() for t in all_tags}
    for tag in extra_tags or []:
        if tag.lower() not in seen:
            all_tags.append(tag)
            seen.add(tag.lower())
    if all_tags:
        cmd.extend(["-tags", ",".join(all_tags)])
        has_template_selection = True

    if automatic:
        cmd.append("-as")
    if exclude_templates:
        cmd.extend(["-et", ",".join(exclude_templates)])

    if not has_template_selection:
        for tdir in BASELINE_TEMPLATE_DIRS:
            cmd.extend(["-t", tdir])

    if options.get("severity"):
        cmd.extend(["-severity", ",".join(options["severity"])])
    else:
        cmd.extend(["-es", EXCLUDED_SEVERITY])

    exclude_tags = list(options.get("exclude_tags", []))
    if "dos" not in [t.lower() for t in exclude_tags]:
        exclude_tags.append("dos")
    cmd.extend(["-etags", ",".join(exclude_tags)])

    for header_name, header_value in headers.items():
        cmd.extend(["-H", f"{header_name}: {header_value}"])

    cmd.extend(extra_args)
    if rate_rps > 0:
        # After extra_args so a user -rl cannot raise it; rate_limit may lower it.
        # Replaces -rate-limit (same flag as -rl) so argv carries one rate flag.
        rate = max(1, math.floor(rate_rps))
        cmd.extend(["-rl", str(min(rate, int(options["rate_limit"])))])
    return cmd
