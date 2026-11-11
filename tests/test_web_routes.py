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


LLM_BODY = {"scan_id": "{scan_id}", "question": "x", "backend": "none"}
TOKEN_BODY = {"name": "t", "scopes": ["scans:read"]}

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
    Case("GET", "/scan/new", "open"),
    Case("GET", "/scan/{scan_id}", "scan"),
    Case("GET", "/templates", "open"),
    Case("GET", "/templates/new", "open"),
    Case("GET", "/templates/{template_id}/edit", "template"),
    Case("GET", "/api/v1/dashboard/summary", "open"),
    Case("GET", "/api/v1/websites", "open"),
    Case("GET", "/api/v1/websites/{hostname}/scans", "open"),
    Case("GET", "/api/v1/websites/{hostname}/trends", "open"),
    Case("POST", "/api/v1/scans", "open", data={"target_url": "https://a.example.com"}),
    Case("GET", "/api/v1/scans", "open"),
    Case("GET", "/api/v1/scans/{scan_id}", "scan"),
    Case("POST", "/api/v1/scans/{scan_id}/cancel", "scan"),
    Case("DELETE", "/api/v1/scans/{scan_id}", "scan"),
    Case("GET", "/api/v1/scans/{scan_id}/report.{fmt}", "scan"),
    Case("GET", "/api/v1/scans/{scan_id}/findings", "scan"),
    Case("GET", "/api/v1/scans/{scan_id}/enrichment", "scan"),
    Case("GET", "/api/v1/templates/status", "open"),
    Case("POST", "/api/v1/templates/update", "admin", json={"source_name": "none"}),
    Case("GET", "/api/v1/scan-templates", "open"),
    Case("GET", "/api/v1/scan-templates/{template_id}", "template"),
    Case("POST", "/api/v1/scan-templates", "open", json={"name": "n"}),
    Case("PUT", "/api/v1/scan-templates/{template_id}", "template", json={"name": "n"}),
    Case("DELETE", "/api/v1/scan-templates/{template_id}", "template"),
    Case("POST", "/api/v1/scan-templates/{template_id}/set-default", "admin"),
    Case("GET", "/api/v1/llm/backends", "open"),
    Case("POST", "/api/v1/llm/ask", "scan", json=LLM_BODY, llm=True),
    Case("POST", "/api/v1/llm/chat", "scan", json=LLM_BODY, llm=True),
    Case("GET", "/api/v1/llm/conversations", "open"),
    Case("GET", "/api/v1/llm/conversations/{conversation_id}", "scan"),
    Case("DELETE", "/api/v1/llm/conversations/{conversation_id}", "scan"),
    Case("POST", "/api/v1/llm/summarize", "scan", json=LLM_BODY, llm=True),
    Case(
        "POST",
        "/api/v1/llm/explain",
        "scan",
        json={**LLM_BODY, "finding_id": "none"},
        llm=True,
    ),
    Case("POST", "/api/v1/llm/remediation-plan", "scan", json=LLM_BODY, llm=True),
    Case("POST", "/api/v1/llm/test-cases", "scan", json=LLM_BODY, llm=True),
    Case("POST", "/api/v1/llm/mitigations", "scan", json=LLM_BODY, llm=True),
    Case(
        "POST",
        "/api/v1/llm/filter-findings",
        "scan",
        json={**LLM_BODY, "criteria": "x"},
        llm=True,
    ),
    Case("GET", "/api/v1/admin/users", "admin"),
    Case("POST", "/api/v1/tokens", "open", json=TOKEN_BODY),
    Case("GET", "/api/v1/tokens", "open"),
    Case("DELETE", "/api/v1/tokens/{token_id}", "open"),
    Case("POST", "/api/v1/targets", "open", json={"host": "app.example.com"}),
    Case("GET", "/api/v1/targets", "open"),
    Case("POST", "/api/v1/targets/{host}/verify", "open"),
    Case("DELETE", "/api/v1/targets/{host}", "open"),
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
    ("method", "path", "status"),
    [
        ("GET", "/health", 200),
        ("GET", "/login", 200),
        ("GET", "/static/main.js", 200),
        ("GET", "/", 303),
        ("GET", "/scan/abc123", 303),
        ("GET", "/api/v1/scans", 401),
        ("POST", "/api/v1/scans", 401),
        ("GET", "/api/v1/llm/backends", 401),
        ("POST", "/api/v1/llm/ask", 401),
        ("GET", "/api/v1/llm/conversations", 401),
        ("GET", "/api/v1/templates/status", 401),
        ("GET", "/api/v1/scan-templates/t1", 401),
        ("GET", "/api/v1/admin/users", 401),
        ("GET", "/auth/users", 303),
        ("GET", "/docs", 404),
        ("GET", "/openapi.json", 404),
    ],
)
def test_anonymous_route_matrix(
    env: WebEnv, method: str, path: str, status: int
) -> None:
    """Scenario Outline: Route matrix without a session."""
    assert env.anonymous().request(method, path).status_code == status


def test_every_unsafe_route_runs_csrf_guard(env: WebEnv) -> None:
    unguarded = [
        (m, p)
        for m, p, ctx in app_routes(env)
        if m in UNSAFE and "csrf_protect" not in dependency_names(ctx.dependant)
    ]
    assert unguarded == []


def case_json(case: Case, resources: dict[str, str]) -> dict[str, Any] | None:
    """Request body with path parameters (e.g. `scan_id`) filled in."""
    if not case.json:
        return None
    return {
        k: v.format_map(resources) if isinstance(v, str) else v
        for k, v in case.json.items()
    }


def _send(client: Any, case: Case, resources: dict[str, str], *, csrf: bool) -> int:
    headers = client.csrf_headers if csrf else {}
    status: int = client.request(
        case.method,
        case.path.format_map(resources),
        json=case_json(case, resources),
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
