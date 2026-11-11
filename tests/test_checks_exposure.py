import json
from urllib.parse import urlsplit

import requests

from haris.checks.findings import prior
from haris.checks.graphql_checks import GraphqlIntrospectionScanner
from haris.checks.listing_checks import DirectoryListingScanner
from haris.checks.openapi_checks import OpenApiScanner
from haris.models import Scope, Severity

from .checks_support import HTML_SHELL, NOT_FOUND, html, run_check, site

JSON = {"Content-Type": "application/json"}
SCHEMA = {
    "data": {
        "__schema": {
            "queryType": {"name": "Query"},
            "types": [{"name": "Query"}, {"name": "User"}],
        }
    }
}
DISABLED = {"errors": [{"message": "GraphQL introspection is not allowed"}]}


def graphql_site(answer: dict, *, post: bool = True, get: bool = True):
    def handler(request: requests.PreparedRequest):
        if urlsplit(request.url or "").path != "/graphql":
            return NOT_FOUND
        if request.method == "POST" and post:
            return 200, JSON, json.dumps(answer).encode()
        if request.method == "GET" and get and "__schema" in (request.url or ""):
            return 200, JSON, json.dumps(answer).encode()
        return 400, JSON, b'{"errors":[{"message":"bad request"}]}'

    return site({}, fallback=handler)


def test_graphql_introspection_over_post_is_reported():
    net = graphql_site(SCHEMA)
    [found] = run_check(GraphqlIntrospectionScanner(), net).findings

    assert found.vuln_class == "graphql_introspection"
    assert found.url.endswith("/graphql")
    assert "Query, User" in found.evidence
    assert found.severity is Severity.MEDIUM
    assert found.confidence_score == prior("graphql_checks.introspection")


def test_graphql_introspection_falls_back_to_get_when_post_is_out_of_scope():
    net = graphql_site(SCHEMA, post=False)
    result = run_check(GraphqlIntrospectionScanner(), net)

    assert len(result.findings) == 1
    assert "POST" not in {r.method for r in net.sent}


def test_disabled_introspection_is_clean():
    assert (
        run_check(GraphqlIntrospectionScanner(), graphql_site(DISABLED)).findings == []
    )


def test_spa_catch_all_is_not_a_graphql_endpoint():
    net = site({}, fallback=html(HTML_SHELL))
    assert run_check(GraphqlIntrospectionScanner(), net).findings == []


def test_graphql_answer_without_types_is_not_introspection():
    partial = {"data": {"__schema": {"queryType": {"name": "Query"}}}}
    assert (
        run_check(GraphqlIntrospectionScanner(), graphql_site(partial)).findings == []
    )


SPEC = json.dumps({"openapi": "3.0.0", "paths": {"/users": {}, "/orders": {}}})


def test_exposed_openapi_document_is_reported_with_path_count():
    net = site({"/openapi.json": (200, JSON, SPEC.encode())})
    [found] = run_check(OpenApiScanner(), net).findings

    assert found.vuln_class == "api_docs_exposed"
    assert found.cwe_id == "CWE-200"
    assert "2 paths" in found.evidence
    assert "openapi" in found.evidence
    assert found.confidence_score == prior("openapi_checks.spec_exposed")


def test_swagger_2_document_at_v2_api_docs_is_reported():
    body = json.dumps({"swagger": "2.0", "paths": {}}).encode()
    net = site({"/v2/api-docs": (200, JSON, body)})
    assert [f.url for f in run_check(OpenApiScanner(), net).findings] == [
        "https://example.com/v2/api-docs"
    ]


def test_spa_catch_all_serves_no_api_spec():
    net = site({}, fallback=html(HTML_SHELL))
    assert run_check(OpenApiScanner(), net).findings == []


def test_html_or_unrelated_json_at_spec_path_is_not_a_spec():
    net = site(
        {
            "/openapi.json": html(b"<h1>Docs</h1>"),
            "/swagger.json": (200, JSON, b'{"name": "pkg"}'),
        }
    )
    assert run_check(OpenApiScanner(), net).findings == []


LISTING = b"<html><head><title>Index of /uploads</title></head><body><pre>a.zip"


def test_directory_listing_is_reported():
    net = site({"/uploads/": html(LISTING)})
    [found] = run_check(DirectoryListingScanner(), net).findings

    assert found.title == "Directory listing enabled: /uploads/"
    assert found.cwe_id == "CWE-548"
    assert found.confidence_score == prior("listing_checks.directory_listing")


def test_python_and_iis_listings_are_recognised():
    python = html(b"<title>Directory listing for /files/</title>")
    iis = html(b"<html>[To Parent Directory]<br><a href=a>a</a></html>")
    net = site({"/files/": python, "/backup/": iis})
    found = run_check(DirectoryListingScanner(), net).findings
    assert sorted(f.url.rsplit("/", 2)[-2] for f in found) == ["backup", "files"]


def test_spa_catch_all_has_no_directory_listing():
    net = site({}, fallback=html(HTML_SHELL))
    assert run_check(DirectoryListingScanner(), net).findings == []


def test_forbidden_and_unrelated_pages_are_not_listings():
    net = site(
        {
            "/uploads/": html(LISTING, status=403),
            "/files/": html(b"<p>Index of our products</p>"),
        }
    )
    assert run_check(DirectoryListingScanner(), net).findings == []


def test_probes_stay_inside_the_request_budget():
    net = site({}, scope=Scope(max_requests=5, rate_limit_rps=1000.0))
    result = run_check(DirectoryListingScanner(), net)
    assert result.findings == [] and len(net.sent) <= 5
