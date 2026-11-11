import base64
import hashlib
import json
import os
import re
from collections.abc import Iterator
from html.parser import HTMLParser
from pathlib import Path

import pytest

from haris.models import (
    Confidence,
    Effort,
    Finding,
    RemediationStep,
    ScanSession,
    ScanState,
    Severity,
    Target,
)
from haris.web.templating import STATIC_DIR, TEMPLATES_DIR

from .test_web_env import WebEnv

VENDOR_DIR = STATIC_DIR / "vendor"
ADMIN_PAGES = [
    "/",
    "/scans",
    "/scan/new",
    "/websites",
    "/website/app.example.com",
    "/templates",
    "/templates/new",
    "/settings",
    "/licenses",
    "/auth/profile",
    "/auth/users",
    "/auth/audit-log",
]
ANONYMOUS_PAGES = ["/login", "/auth/register"]
FIRST_RUN_PAGES = ["/login", "/auth/setup"]
URL_ATTRS = {"src", "href", "action", "formaction"}


class Page:
    def __init__(self, path: str, html: str, nonce: str) -> None:
        self.path = path
        self.html = html
        self.nonce = nonce


class Inspector(HTMLParser):
    def __init__(self) -> None:
        super().__init__()
        self.handlers: list[str] = []
        self.scripts: list[dict[str, str | None]] = []
        self.styles: list[dict[str, str | None]] = []
        self.urls: list[tuple[str, str, str]] = []
        self.hx_on: list[str] = []
        self.data_actions: set[str] = set()

    def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        attributes = dict(attrs)
        for name, value in attrs:
            if re.fullmatch(r"on[a-z]+", name):
                self.handlers.append(f"<{tag} {name}>")
            if name.startswith("hx-on"):
                self.hx_on.append(f"<{tag} {name}>")
            if name == "data-action" and value:
                self.data_actions.add(value)
            if name in URL_ATTRS and value:
                self.urls.append((tag, name, value))
        if tag == "script":
            self.scripts.append(attributes)
        if tag == "style":
            self.styles.append(attributes)


def inspect(html: str) -> Inspector:
    parser = Inspector()
    parser.feed(html)
    return parser


def sri(path: Path) -> str:
    digest = hashlib.sha384(path.read_bytes()).digest()
    return "sha384-" + base64.b64encode(digest).decode()


@pytest.fixture(scope="module")
def pages(tmp_path_factory: pytest.TempPathFactory) -> Iterator[list[Page]]:
    env = WebEnv(tmp_path_factory.mktemp("render"))
    session = ScanSession(
        session_id="rich0001",
        target=Target(base_url="https://app.example.com"),
        started_at="2026-01-02T03:04:05+00:00",
        finished_at="2026-01-02T03:09:05+00:00",
        profile_name="quick",
        all_findings=[
            Finding(
                title="Missing HSTS <b>header</b>",
                description="No HSTS.",
                severity=Severity.MEDIUM,
                confidence=Confidence.CONFIRMED,
                url="https://app.example.com",
                remediation="Add the header.",
                scanner="header_checks",
                finding_id="f001",
            )
        ],
        remediation_steps=[
            RemediationStep(
                title="Add headers",
                description="Deploy.",
                effort=Effort.QUICK_WIN,
                impact=Severity.MEDIUM,
                finding_count=1,
            )
        ],
    )
    session.scan_state = ScanState.COMPLETED
    env.state.store.save_session(session, owner_user_id=env.admin.user_id)
    template_id = env.add_template(env.admin)
    running = env.add_scan(
        env.admin, url="https://run.example.com", state=ScanState.RUNNING
    )
    queued = env.add_scan(
        env.admin, url="https://queue.example.com", state=ScanState.PENDING
    )
    failed = env.add_scan(
        env.admin,
        state=ScanState.FAILED,
        errors=["boom <script>alert(1)</script>"],
    )
    paths = [
        *ADMIN_PAGES,
        "/scan/rich0001",
        f"/scan/{running}",
        f"/scan/{queued}",
        f"/scan/{failed}",
        f"/templates/{template_id}/edit",
    ]
    rendered: list[Page] = []
    admin = env.browser(env.admin)
    for path in paths:
        response = admin.get(path)
        assert response.status_code == 200, path
        nonce = re.search(
            r"'nonce-([^']+)'", response.headers["content-security-policy"]
        )
        assert nonce
        rendered.append(Page(path, response.text, nonce.group(1)))
    for path in ANONYMOUS_PAGES:
        response = env.anonymous().get(path)
        assert response.status_code == 200, path
        nonce = re.search(
            r"'nonce-([^']+)'", response.headers["content-security-policy"]
        )
        assert nonce
        rendered.append(Page(path, response.text, nonce.group(1)))
    previous_setup_token = os.environ.get("HARIS_SETUP_TOKEN")
    os.environ["HARIS_SETUP_TOKEN"] = "render-setup-token"
    try:
        first_run = WebEnv(tmp_path_factory.mktemp("first-run"), seed_users=False)
        for path in FIRST_RUN_PAGES:
            response = first_run.anonymous().get(path)
            assert response.status_code == 200, path
            nonce = re.search(
                r"'nonce-([^']+)'", response.headers["content-security-policy"]
            )
            assert nonce
            rendered.append(Page(f"first-run {path}", response.text, nonce.group(1)))
    finally:
        if previous_setup_token is None:
            os.environ.pop("HARIS_SETUP_TOKEN", None)
        else:
            os.environ["HARIS_SETUP_TOKEN"] = previous_setup_token
    yield rendered


def test_no_inline_event_handlers(pages: list[Page]) -> None:
    found = {p.path: inspect(p.html).handlers for p in pages}
    assert {k: v for k, v in found.items() if v} == {}


def test_no_htmx_eval_attributes(pages: list[Page]) -> None:
    assert [h for p in pages for h in inspect(p.html).hx_on] == []


def test_every_script_has_src_nonce_or_is_data(pages: list[Page]) -> None:
    for page in pages:
        for script in inspect(page.html).scripts:
            ok = (
                script.get("src")
                or script.get("type") == "application/json"
                or script.get("nonce") == page.nonce
            )
            assert ok, (page.path, script)


def test_every_inline_style_block_has_nonce(pages: list[Page]) -> None:
    for page in pages:
        for style in inspect(page.html).styles:
            assert style.get("nonce") == page.nonce, page.path


def test_no_javascript_urls_or_third_party_assets(pages: list[Page]) -> None:
    for page in pages:
        for tag, _attr, value in inspect(page.html).urls:
            assert not value.lower().startswith("javascript:"), (page.path, value)
            if tag in {"script", "link"}:
                assert not re.match(r"(https?:)?//", value), (page.path, value)


def test_every_vendored_script_has_matching_sri(pages: list[Page]) -> None:
    seen: set[str] = set()
    for page in pages:
        for script in inspect(page.html).scripts:
            src = script.get("src") or ""
            if src.startswith("/static/vendor/"):
                file = VENDOR_DIR / src.removeprefix("/static/vendor/")
                assert script.get("integrity") == sri(file), src
                seen.add(src)
    assert {
        "/static/vendor/htmx.min.js",
        "/static/vendor/purify.min.js",
        "/static/vendor/marked.umd.js",
        "/static/vendor/chart.umd.min.js",
    } <= seen


def test_vendor_readme_hashes_match_files() -> None:
    readme = (VENDOR_DIR / "README").read_text()
    for file in sorted(
        p for p in VENDOR_DIR.rglob("*") if p.suffix in {".js", ".woff2"}
    ):
        name = file.relative_to(VENDOR_DIR).as_posix()
        assert hashlib.sha256(file.read_bytes()).hexdigest() in readme, name
        if file.suffix == ".js":
            assert sri(file) in readme, name


def test_all_template_sources_are_free_of_inline_code() -> None:
    for file in TEMPLATES_DIR.rglob("*.html"):
        text = file.read_text()
        rel = file.relative_to(TEMPLATES_DIR)
        assert not re.search(r"\son[a-z]+\s*=", text), rel
        assert "<style" not in text, rel
        for tag in re.findall(r"<script\b[^>]*>", text, re.I):
            assert re.search(r'\b(src|type)="', tag) or "nonce=" in tag, (rel, tag)


def test_every_data_action_has_a_handler(pages: list[Page]) -> None:
    scripts = "\n".join(p.read_text() for p in (STATIC_DIR / "js").glob("*.js"))
    for page in pages:
        for action in inspect(page.html).data_actions:
            assert re.search(rf"['\"]?{re.escape(action)}['\"]?\s*:", scripts), (
                page.path,
                action,
            )


def test_every_script_and_stylesheet_reference_exists(pages: list[Page]) -> None:
    for page in pages:
        for tag, _attr, value in inspect(page.html).urls:
            if tag in {"script", "link"} and value.startswith("/static/"):
                assert (STATIC_DIR / value.removeprefix("/static/")).is_file(), value


def test_markdown_is_sanitised_before_insertion() -> None:
    main = (STATIC_DIR / "main.js").read_text()
    assert "DOMPurify.sanitize(marked.parse(" in main
    for file in (STATIC_DIR / "js").glob("*.js"):
        assert "marked.parse(" not in file.read_text(), file.name


def test_page_data_blocks_are_valid_json(pages: list[Page]) -> None:
    for page in pages:
        for block in re.findall(
            r'<script type="application/json" id="page-data">(.*?)</script>',
            page.html,
            re.S,
        ):
            assert isinstance(json.loads(block), dict), page.path


def test_untrusted_text_is_escaped(pages: list[Page]) -> None:
    detail = next(p for p in pages if p.path == "/scan/rich0001")
    assert "Missing HSTS <b>header</b>" not in detail.html
    failed = next(
        p for p in pages if p.path.startswith("/scan/scan") and "boom" in p.html
    )
    assert "<script>alert(1)</script>" not in failed.html
