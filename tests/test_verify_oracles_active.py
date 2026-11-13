import base64
import binascii
import re
from urllib.parse import parse_qs, urlsplit

import pytest
import requests

from haris.models import (
    CorrelatedFinding,
    Scope,
    VerificationMethod,
    VerificationOracle,
    VerificationTier,
)
from haris.verify.oracles import ORACLES
from haris.verify.oracles_active import boolean_sqli, code_eval, file_marker
from haris.verify.probe import Prober, VerifyBudgetExhausted
from haris.verify.replay import CAP_REASON, oracle_names, replay
from haris.verify.settings import load_verify_settings
from tests.checks_support import html, site
from tests.fake_transport import FakeNet
from tests.verify_server import case, fast_settings

T = VerificationTier
POST = Scope(rate_limit_rps=1000.0, allowed_methods=["GET", "POST", "HEAD", "OPTIONS"])
PASSWD = b"root:x:0:0:root:/root:/bin/bash"
UPLOAD = (
    'curl "https://example.com/up" -F MAX_FILE_SIZE=100000 '
    '-F Upload=Upload -F "uploaded=@a.jpg;filename=old"'
)
DATA = 'curl "https://example.com/fi/?page=data:;base64,AAAA"'
FILE_PART = re.compile(
    rb'filename="([^"]*)"\r\nContent-Type: application/octet-stream\r\n\r\n(.*?)\r\n',
    re.DOTALL,
)
PHP_MARKER = re.compile(rb"<\?php echo '([0-9a-f]+)'\.'([0-9a-f]+)';\?>")


def _query(request: requests.PreparedRequest, name: str) -> str:
    return parse_qs(urlsplit(request.url or "").query).get(name, [""])[0]


def _file_part(request: requests.PreparedRequest) -> tuple[str, str]:
    body = request.body if isinstance(request.body, bytes) else b""
    match = FILE_PART.search(body)
    if match is None:
        return "", ""
    return match.group(1).decode(), match.group(2).decode()


def _php_marker(value: str) -> str:
    prefix, _, _ = load_verify_settings().code_eval_wrapper.partition("{b64}")
    if not value.startswith(prefix):
        return ""
    try:
        raw = base64.b64decode(value[len(prefix) :], validate=True)
    except binascii.Error:
        return ""
    match = PHP_MARKER.fullmatch(raw)
    if match is None:
        return ""
    return (match.group(1) + match.group(2)).decode()


def _run(net: FakeNet, finding: CorrelatedFinding, **updates: object) -> None:
    replay([finding], net.client, fast_settings(**updates))


@pytest.mark.parametrize("mode", ["positive", "control", "other", "cap"])
def test_multipart_marker_file(mode: str) -> None:
    """Scenario: Multipart marker file."""
    seen: list[str] = []

    def upload(request: requests.PreparedRequest) -> tuple[int, dict[str, str], bytes]:
        filename, content = _file_part(request)
        echoed = filename if filename and filename == content else ""
        if echoed:
            seen.append(echoed)
        body = "".join(seen) if mode == "control" else echoed
        return html(f"<html>{body}</html>".encode())

    if mode == "other":
        net = site(
            fallback=lambda request: html(
                PASSWD if "passwd" in _query(request, "q") else b"ok"
            )
        )
        finding = case("Path Traversal", "https://example.com/lfi?q=1")
        _run(net, finding)
        assert finding.canonical.verification.oracle == (
            VerificationOracle.PATH_TRAVERSAL
        )
        assert finding.canonical.verification.tier == T.REPLAY_VERIFIED
        assert all(
            "multipart/form-data" not in sent.headers.get("Content-Type", "")
            for sent in net.sent
        )
        return

    finding = case(
        "Reflected Cross Site Scripting",
        "https://example.com/up",
        parameter="uploaded",
        method="POST",
    )
    finding.canonical.request_example = UPLOAD
    if mode == "cap":
        names = oracle_names(finding)
        assert names[-1] == "file_marker"
        settings = fast_settings()
        cost = sum(ORACLES[name].cost(settings) for name in names)
        net = site(fallback=upload, scope=POST)
        report = replay([finding], net.client, fast_settings(max_requests=cost - 1))
        assert net.sent == []
        assert finding.canonical.verification.method == VerificationMethod.NONE
        assert report.skipped[finding.canonical.finding_id] == CAP_REASON
        limited = site(fallback=upload, scope=POST)
        prober = Prober(limited.client, 1)
        with pytest.raises(VerifyBudgetExhausted):
            file_marker(finding.canonical, prober, settings)
        assert len(limited.sent) == 1
        return

    net = site(fallback=upload, scope=POST)
    _run(net, finding)
    verification = finding.canonical.verification
    multipart = [
        sent
        for sent in net.sent
        if "multipart/form-data" in sent.headers.get("Content-Type", "")
    ]
    assert len(multipart) == load_verify_settings().file_marker_cost
    raw = multipart[0].body
    body = raw if isinstance(raw, bytes) else (raw or "").encode()
    assert b'name="Upload"' in body
    assert b'name="MAX_FILE_SIZE"' in body
    if mode == "positive":
        assert verification.tier == T.REPLAY_VERIFIED
        assert verification.oracle == VerificationOracle.FILE_MARKER
        return
    assert verification.tier == T.UNVERIFIED
    assert verification.method == VerificationMethod.REPLAY
    assert verification.oracle == VerificationOracle.FILE_MARKER


@pytest.mark.parametrize("mode", ["positive", "control", "other", "cap"])
def test_php_marker_after_the_data_wrapper(mode: str) -> None:
    """Scenario: PHP marker after the data wrapper."""
    seen: list[str] = []

    def fi(request: requests.PreparedRequest) -> tuple[int, dict[str, str], bytes]:
        marker = _php_marker(_query(request, "page"))
        if marker:
            seen.append(marker)
        body = (marker + "".join(seen)) if mode == "control" else (marker or "ok")
        return html(body.encode())

    if mode == "other":
        net = site(
            fallback=lambda request: html(
                PASSWD if "passwd" in _query(request, "q") else b"ok"
            )
        )
        finding = case("Path Traversal", "https://example.com/lfi?q=1")
        _run(net, finding)
        assert finding.canonical.verification.oracle == (
            VerificationOracle.PATH_TRAVERSAL
        )
        assert "code_eval" not in oracle_names(finding)
        return

    finding = case("Command execution", "https://example.com/fi", parameter="page")
    finding.canonical.request_example = DATA
    if mode == "cap":
        names = oracle_names(finding)
        assert names == ["timing_cmd", "code_eval"]
        settings = fast_settings()
        cost = sum(ORACLES[name].cost(settings) for name in names)
        net = site(fallback=fi)
        report = replay([finding], net.client, fast_settings(max_requests=cost - 1))
        assert net.sent == []
        assert report.skipped[finding.canonical.finding_id] == CAP_REASON
        limited = site(fallback=fi)
        with pytest.raises(VerifyBudgetExhausted):
            code_eval(finding.canonical, Prober(limited.client, 1), settings)
        assert len(limited.sent) == 1
        return

    net = site(fallback=fi)
    _run(net, finding)
    verification = finding.canonical.verification
    assert any("data%3A" in (sent.url or "") for sent in net.sent)
    if mode == "positive":
        assert verification.tier == T.REPLAY_VERIFIED
        assert verification.oracle == VerificationOracle.CODE_EVAL
        return
    assert verification.tier == T.UNVERIFIED
    assert verification.oracle == VerificationOracle.CODE_EVAL


@pytest.mark.parametrize("mode", ["positive", "control", "other", "cap"])
def test_boolean_sql_pair(mode: str) -> None:
    """Scenario: Boolean SQL pair."""

    def sqli(request: requests.PreparedRequest) -> tuple[int, dict[str, str], bytes]:
        value = _query(request, "id")
        if mode == "control" or "OR 1=1" in value:
            kind = "exists"
        elif "AND 1=2" in value:
            kind = "missing"
        else:
            kind = "form"
        return html(f"<html>{kind}:{value}</html>".encode())

    if mode == "other":
        net = site(
            fallback=lambda request: html(
                f"<html>{_query(request, 'q')}</html>".encode()
            )
        )
        finding = case("Cross Site Scripting", "https://example.com/search?q=1")
        _run(net, finding)
        assert finding.canonical.verification.oracle == VerificationOracle.REFLECTION
        assert finding.canonical.verification.tier == T.REPLAY_VERIFIED
        assert all("OR%201%3D1" not in (sent.url or "") for sent in net.sent)
        return

    finding = case("SQL Injection", "https://example.com/sqli?id=1", parameter="id")
    if mode == "cap":
        names = oracle_names(finding)
        assert names == ["error_signature", "boolean_sqli"]
        settings = fast_settings()
        cost = sum(ORACLES[name].cost(settings) for name in names)
        net = site(fallback=sqli)
        report = replay([finding], net.client, fast_settings(max_requests=cost - 1))
        assert net.sent == []
        assert report.skipped[finding.canonical.finding_id] == CAP_REASON
        limited = site(fallback=sqli)
        with pytest.raises(VerifyBudgetExhausted):
            boolean_sqli(finding.canonical, Prober(limited.client, 1), settings)
        assert len(limited.sent) == 1
        return

    net = site(fallback=sqli)
    _run(net, finding)
    verification = finding.canonical.verification
    if mode == "positive":
        assert verification.tier == T.REPLAY_VERIFIED
        assert verification.oracle == VerificationOracle.BOOLEAN_SQLI
        return
    assert verification.tier == T.UNVERIFIED
    assert verification.oracle == VerificationOracle.BOOLEAN_SQLI


def test_active_oracle_settings_match_verify_yaml() -> None:
    settings = load_verify_settings()
    assert settings.code_eval_template == "<?php echo '{left}'.'{right}';?>"
    assert settings.code_eval_wrapper == "data:;base64,{b64}"
    assert settings.code_eval_cost == 2
    assert settings.boolean_true == "{prefix}' OR 1=1#"
    assert settings.boolean_false == "{prefix}' AND 1=2#"
    assert settings.boolean_control == "{prefix}' OR 1=1#"
    assert settings.boolean_repeats == 2
    assert settings.file_marker_cost == 2
    assert ORACLES["file_marker"].cost(settings) == settings.file_marker_cost
    assert ORACLES["code_eval"].cost(settings) == settings.code_eval_cost
    assert ORACLES["boolean_sqli"].cost(settings) == settings.boolean_repeats * 3
