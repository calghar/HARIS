from collections.abc import Iterator
from typing import Any, NamedTuple

import pytest
from fastapi.routing import iter_route_contexts

from haris.auth.public import PUBLIC_ROUTES

from .test_web_env import WebEnv, stub_scan_runner

UNSAFE = {"POST", "PUT", "PATCH", "DELETE"}


class Case(NamedTuple):
    method: str
    path: str
    scope: str  # open | admin | scan | template | website
    json: dict[str, Any] | None = None
    data: dict[str, str] | None = None
    llm: bool = False  # 5xx expected: the test backend does not exist


LLM_BODY = {"question": "x", "backend": "none"}

CASES = [
    Case("GET", "/auth/profile", "open"),
    Case("POST", "/auth/profile", "open", data={"display_name": "A"}),
    Case("DELETE", "/auth/profile/sessions/{token}", "open"),
    Case("GET", "/auth/users", "admin"),
    Case(
        "POST", "/auth/users", "admin", data={"email": "n@example.com", "password": "x"}
    ),
    Case("PUT", "/auth/users/{user_id}", "admin", data={"role": "user"}),
    Case("DELETE", "/auth/users/{user_id}", "admin"),
    Case("GET", "/auth/audit-log", "admin"),
    Case("GET", "/", "open"),
    Case("GET", "/scans", "open"),
    Case("GET", "/settings", "admin"),
    Case("GET", "/licenses", "open"),
    Case("GET", "/websites", "open"),
    Case("GET", "/website/{hostname}", "website"),
    Case("GET", "/api/dashboard/summary", "open"),
    Case("GET", "/api/websites", "open"),
    Case("GET", "/api/website/{hostname}/scans", "open"),
    Case("GET", "/api/website/{hostname}/trends", "open"),
    Case("GET", "/scan/new", "open"),
    Case("GET", "/scan/{scan_id}", "scan"),
    Case(
        "POST", "/api/scan/start", "open", data={"target_url": "https://a.example.com"}
    ),
    Case("GET", "/api/scan/{scan_id}/status", "scan"),
    Case("GET", "/api/scan/{scan_id}/report/{fmt}", "scan"),
    Case("GET", "/api/scans", "open"),
    Case("DELETE", "/api/scan/{scan_id}", "scan"),
    Case("GET", "/api/scan/{scan_id}/findings", "scan"),
    Case("GET", "/templates", "open"),
    Case("GET", "/templates/new", "open"),
    Case("GET", "/templates/{template_id}/edit", "template"),
    Case("GET", "/api/templates/status", "open"),
    Case("POST", "/api/templates/update", "admin", json={"source_name": "none"}),
    Case("GET", "/api/scan-templates", "open"),
    Case("GET", "/api/scan-templates/{template_id}", "template"),
    Case("POST", "/api/scan-templates", "open", json={"name": "n"}),
    Case("PUT", "/api/scan-templates/{template_id}", "template", json={"name": "n"}),
    Case("DELETE", "/api/scan-templates/{template_id}", "template"),
    Case("POST", "/api/scan-templates/{template_id}/set-default", "admin"),
    Case("POST", "/api/scan/{scan_id}/summarize", "scan", json=LLM_BODY, llm=True),
    Case(
        "POST",
        "/api/scan/{scan_id}/explain/{finding_id}",
        "scan",
        json=LLM_BODY,
        llm=True,
    ),
    Case(
        "POST", "/api/scan/{scan_id}/remediation-plan", "scan", json=LLM_BODY, llm=True
    ),
    Case("POST", "/api/scan/{scan_id}/test-cases", "scan", json=LLM_BODY, llm=True),
    Case("POST", "/api/scan/{scan_id}/mitigations", "scan", json=LLM_BODY, llm=True),
    Case("POST", "/api/scan/{scan_id}/filter-findings", "scan", json=LLM_BODY),
    Case("GET", "/api/llm/backends", "open"),
    Case("GET", "/api/scan/{scan_id}/enrichment", "scan"),
    Case("POST", "/api/scan/{scan_id}/ask", "scan", json=LLM_BODY, llm=True),
    Case("POST", "/api/scan/{scan_id}/chat", "scan", json=LLM_BODY, llm=True),
    Case("GET", "/api/scan/{scan_id}/chat/{conversation_id}", "scan"),
    Case("DELETE", "/api/scan/{scan_id}/chat/{conversation_id}", "scan"),
]


def app_routes(env: WebEnv) -> Iterator[tuple[str, str, Any]]:
    for ctx in iter_route_contexts(env.app.routes):
        for method in sorted((ctx.methods or set()) - {"HEAD", "OPTIONS"}):
            yield method, str(ctx.path), ctx


def dependency_names(dependant: Any) -> set[str]:
    names = {getattr(dependant.call, "__name__", "")}
    for sub in dependant.dependencies:
        names |= dependency_names(sub)
    return names


@pytest.fixture(scope="module")
def env(tmp_path_factory: pytest.TempPathFactory) -> Iterator[WebEnv]:
    with pytest.MonkeyPatch.context() as patch:
        stub_scan_runner(patch)
        yield WebEnv(tmp_path_factory.mktemp("routes"))


def test_route_table_covers_every_route(env: WebEnv) -> None:
    table = {(c.method, c.path) for c in CASES}
    actual = {
        (m, p)
        for m, p, _ in app_routes(env)
        if (p, m) not in PUBLIC_ROUTES and not p.startswith("/static")
    }
    assert actual == table


def test_only_allow_listed_routes_are_public(env: WebEnv) -> None:
    open_routes = [
        (m, p)
        for m, p, ctx in app_routes(env)
        if ctx.dependant is not None
        and not dependency_names(ctx.dependant) & {"require_user", "require_admin"}
    ]
    assert {(p, m) for m, p in open_routes} == set(PUBLIC_ROUTES)


def test_every_allow_listed_route_exists(env: WebEnv) -> None:
    routes = {(p, m) for m, p, _ in app_routes(env)}
    assert set(PUBLIC_ROUTES) <= routes


@pytest.mark.parametrize(
    ("path", "status"),
    [
        ("/health", 200),
        ("/login", 200),
        ("/static/main.js", 200),
        ("/", 303),
        ("/scan/abc123", 303),
        ("/api/scans", 401),
        ("/api/llm/backends", 401),
        ("/api/templates/status", 401),
        ("/api/scan-templates/t1", 401),
        ("/auth/users", 303),
        ("/docs", 404),
        ("/openapi.json", 404),
    ],
)
def test_anonymous_route_matrix(env: WebEnv, path: str, status: int) -> None:
    assert env.anonymous().get(path).status_code == status


def test_every_unsafe_route_runs_csrf_guard(env: WebEnv) -> None:
    unguarded = [
        (m, p)
        for m, p, ctx in app_routes(env)
        if m in UNSAFE and "csrf_protect" not in dependency_names(ctx.dependant)
    ]
    assert unguarded == []


def _send(client: Any, case: Case, resources: dict[str, str], *, csrf: bool) -> int:
    headers = client.csrf_headers if csrf else {}
    status: int = client.request(
        case.method,
        case.path.format_map(resources),
        json=case.json,
        data=case.data,
        headers=headers,
    ).status_code
    return status


def reached(status: int, case: Case) -> bool:
    """The handler ran: no auth/ownership denial and no crash."""
    return status not in {401, 403, 404} and (case.llm or status < 500)


def _id(case: Case) -> str:
    return f"{case.method} {case.path}"


@pytest.mark.parametrize("case", CASES, ids=_id)
def test_anonymous_is_rejected(env: WebEnv, case: Case) -> None:
    status = _send(env.anonymous(), case, env.resources(env.alice), csrf=False)
    assert status == (401 if case.path.startswith("/api/") else 303)


@pytest.mark.parametrize("case", CASES, ids=_id)
def test_owner_reaches_handler(env: WebEnv, case: Case) -> None:
    status = _send(env.browser(env.alice), case, env.resources(env.alice), csrf=True)
    assert status == 403 if case.scope == "admin" else reached(status, case)


@pytest.mark.parametrize("case", CASES, ids=_id)
def test_other_user_sees_not_found_on_foreign_resources(
    env: WebEnv, case: Case
) -> None:
    resources = env.resources(env.alice, env.bob)
    status = _send(env.browser(env.bob), case, resources, csrf=True)
    if case.scope == "admin":
        assert status == 403
    elif case.scope in {"scan", "template", "website"}:
        assert status == 404
    else:
        assert reached(status, case)


@pytest.mark.parametrize("case", CASES, ids=_id)
def test_admin_reaches_handler(env: WebEnv, case: Case) -> None:
    resources = env.resources(env.alice, env.admin)
    status = _send(env.browser(env.admin), case, resources, csrf=True)
    assert reached(status, case)
