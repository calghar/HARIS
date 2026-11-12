_NUMBER_MIN = 0
_NUMBER_MAX = 100_000_000
_TEXT_MAX_CHARS = 2_000
_LIST_MAX_ITEMS = 100
_LIST_ITEM_MAX_CHARS = 500
_NUMBER = "number"
_BOOL = "bool"
_TEXT = "text"
_LIST = "list"
_STRINGS = "strings"
_NUMBER_KEYS = (
    "active_minutes",
    "bulk_size",
    "cert_expiry_warn_days",
    "concurrency",
    "delay_ms",
    "dns_timeout",
    "max_body_bytes",
    "max_cookie_lifetime_seconds",
    "max_host_errors",
    "max_instances",
    "max_links",
    "max_prompts",
    "max_scan_time",
    "max_tokens_per_prompt",
    "passive_minutes",
    "phase2_timeout_s",
    "rate_limit",
    "spider_minutes",
    "threads",
    "timeout",
    "timeout_per_request",
)
_POSITIVE_KEYS = frozenset({"phase2_timeout_s"})
_BOOL_KEYS = (
    "automatic_scan",
    "check_cors",
    "check_debug_endpoints",
    "check_error_pages",
    "check_html_comments",
    "check_redirect",
    "check_sensitive_paths",
    "check_version_endpoints",
    "enable_interactsh",
    "follow_redirects",
    "skip_tech_detection",
    "update_templates",
)
_TEXT_KEYS = (
    "external_endpoint",
    "internal_endpoint",
    "modules",
    "ports",
    "provider",
    "scope",
)
_LIST_KEYS = (
    "exclude_tags",
    "extra_args",
    "nse_scripts",
    "plugins",
    "probes",
    "script_categories",
    "severity",
    "system_prompt_markers",
    "tags",
    "template_dirs",
    "templates",
)
_VALUE_KINDS: dict[str, str] = {
    **dict.fromkeys(_NUMBER_KEYS, _NUMBER),
    **dict.fromkeys(_BOOL_KEYS, _BOOL),
    **dict.fromkeys(_TEXT_KEYS, _TEXT),
    **dict.fromkeys(_LIST_KEYS, _LIST),
    "tuning": _STRINGS,
}
