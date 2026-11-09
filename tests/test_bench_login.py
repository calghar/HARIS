import importlib.util
import logging
import subprocess
from pathlib import Path
from types import ModuleType
from typing import Any
from urllib.parse import parse_qs

import httpx
import pytest
import yaml

RUN_PY = Path(__file__).resolve().parent.parent / "bench" / "run.py"
BASE_URL = "http://127.0.0.1:1"
LOGIN_TOKEN = "a1b2c3"
SECURITY_TOKEN = "d4e5f6"
TOKEN_PAGE = "<input type='hidden' name='user_token' value='{}' />"
DVWA_COOKIES = "PHPSESSID=sess1; security=low"
WEBGOAT_SESSION = "JSESSIONID=sess9"

Posts = list[tuple[str, dict[str, list[str]]]]


def load_runner() -> ModuleType:
    spec = importlib.util.spec_from_file_location("bench_run_login", RUN_PY)
    assert spec and spec.loader
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


runner = load_runner()


def dvwa_transport(posts: Posts, *, accept: bool = True) -> httpx.MockTransport:
    def handler(request: httpx.Request) -> httpx.Response:
        path = request.url.path
        if request.method == "POST":
            form = parse_qs(request.content.decode())
            posts.append((path, form))
            if path == "/security.php":
                return httpx.Response(
                    200, headers={"Set-Cookie": "security=low; path=/"}
                )
            valid = form.get("user_token") == [LOGIN_TOKEN] and accept
            return httpx.Response(
                302, headers={"Location": "index.php" if valid else "login.php"}
            )
        pages = {
            "/login.php": TOKEN_PAGE.format(LOGIN_TOKEN),
            "/security.php": TOKEN_PAGE.format(SECURITY_TOKEN),
            "/index.php": "home",
        }
        headers = (
            {"Set-Cookie": "PHPSESSID=sess1; path=/"} if path == "/login.php" else {}
        )
        return httpx.Response(200, text=pages[path], headers=headers)

    return httpx.MockTransport(handler)


def webgoat_transport(posts: Posts, *, accept: bool = True) -> httpx.MockTransport:
    def handler(request: httpx.Request) -> httpx.Response:
        path = request.url.path
        if request.method == "POST":
            posts.append((path, parse_qs(request.content.decode())))
            if path == "/WebGoat/login":
                if not accept:
                    return httpx.Response(
                        302, headers={"Location": "/WebGoat/login?error"}
                    )
                return httpx.Response(
                    302,
                    headers={
                        "Location": "/WebGoat/welcome.mvc",
                        "Set-Cookie": f"{WEBGOAT_SESSION}; path=/WebGoat",
                    },
                )
            return httpx.Response(200, text="registration form")
        if path == "/WebGoat/welcome.mvc" and WEBGOAT_SESSION in request.headers.get(
            "cookie", ""
        ):
            return httpx.Response(200, text="welcome")
        if path == "/WebGoat/welcome.mvc":
            return httpx.Response(302, headers={"Location": "/WebGoat/login"})
        return httpx.Response(200, text="login form")

    return httpx.MockTransport(handler)


class TestDvwaLogin:
    def test_login_and_security_forms_carry_their_own_csrf_token(self) -> None:
        posts: Posts = []
        cookies = runner.login_dvwa(BASE_URL, dvwa_transport(posts))
        assert cookies == DVWA_COOKIES
        assert posts == [
            (
                "/login.php",
                {
                    "username": ["admin"],
                    "password": ["password"],
                    "Login": ["Login"],
                    "user_token": [LOGIN_TOKEN],
                },
            ),
            (
                "/security.php",
                {
                    "security": ["low"],
                    "seclev_submit": ["Submit"],
                    "user_token": [SECURITY_TOKEN],
                },
            ),
        ]

    def test_rejected_login_raises_instead_of_scanning_unauthenticated(self) -> None:
        with pytest.raises(RuntimeError, match="DVWA login was rejected"):
            runner.login_dvwa(BASE_URL, dvwa_transport([], accept=False))


class TestWebgoatLogin:
    def test_registers_then_logs_in_and_returns_the_session_cookie(self) -> None:
        posts: Posts = []
        cookies = runner.login_webgoat(BASE_URL, webgoat_transport(posts))
        assert cookies == WEBGOAT_SESSION
        register, login = posts
        assert register[0] == "/WebGoat/register.mvc"
        assert register[1]["matchingPassword"] == register[1]["password"]
        assert register[1]["agree"] == ["agree"]
        assert login == (
            "/WebGoat/login",
            {"username": [runner.WEBGOAT_USER], "password": [runner.WEBGOAT_PASSWORD]},
        )

    def test_rejected_login_raises_instead_of_scanning_unauthenticated(self) -> None:
        with pytest.raises(RuntimeError, match="WebGoat login was rejected"):
            runner.login_webgoat(BASE_URL, webgoat_transport([], accept=False))


class TestSessionHandover:
    def run_with_session(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch, cookie: str | None
    ) -> dict[str, Any]:
        seen: dict[str, Any] = {}

        def fake_run(cmd: list[str], **kwargs: Any) -> subprocess.CompletedProcess[str]:
            seen.update(cmd=cmd, env=kwargs.get("env"))
            if "--config" in cmd:
                seen["config"] = yaml.safe_load(
                    Path(cmd[cmd.index("--config") + 1]).read_text()
                )
            (tmp_path / "out" / "report.json").write_text("{}")
            echoed = f"Cookie: {cookie}" if cookie else "no session"
            return subprocess.CompletedProcess(cmd, 0, echoed, echoed)

        (tmp_path / "out").mkdir()
        monkeypatch.setattr(runner.subprocess, "run", fake_run)
        runner.run_haris(
            ["haris"],
            BASE_URL,
            "quick",
            tmp_path / "out",
            tmp_path / "r.json",
            (),
            cookie,
        )
        return seen

    def test_session_goes_through_env_and_config_not_argv_or_logs(
        self,
        tmp_path: Path,
        monkeypatch: pytest.MonkeyPatch,
        caplog: pytest.LogCaptureFixture,
    ) -> None:
        caplog.set_level(logging.DEBUG)
        seen = self.run_with_session(tmp_path, monkeypatch, DVWA_COOKIES)
        assert seen["env"][runner.AUTH_HEADER_ENV] == DVWA_COOKIES
        assert seen["config"]["target"]["auth"] == {
            "method": "header",
            "header_name": "Cookie",
        }
        assert DVWA_COOKIES not in " ".join(seen["cmd"])
        assert not list((tmp_path / "out").glob("*.yaml"))
        for log in ("stdout.log", "stderr.log"):
            assert (tmp_path / "out" / log).read_text() == f"Cookie: {runner.REDACTED}"
        assert DVWA_COOKIES not in caplog.text

    def test_no_session_leaves_command_and_environment_untouched(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        seen = self.run_with_session(tmp_path, monkeypatch, None)
        assert "--config" not in seen["cmd"]
        assert seen["env"] is None

    def test_each_run_logs_in_again_and_external_targets_without_login_get_none(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        sessions: list[tuple[str, str | None]] = []
        logins = iter(["s1", "s2"])

        def fake_run_haris(*args: Any) -> None:
            sessions.append((args[1], args[-1]))

        monkeypatch.setattr(runner, "compose", lambda *a: None)
        monkeypatch.setattr(runner, "resolve_base_url", lambda t: BASE_URL)
        monkeypatch.setattr(runner, "wait_healthy", lambda *a: None)
        monkeypatch.setattr(runner, "score", lambda *a: None)
        monkeypatch.setattr(runner, "run_haris", fake_run_haris)
        monkeypatch.setitem(runner.LOGIN, "dvwa", lambda url: next(logins))
        monkeypatch.setitem(runner.PREPARE, "dvwa", lambda url: None)
        args = runner.parse_args(["--runs", "2"])
        runner.bench_target("dvwa", args, tmp_path)
        runner.bench_target("juice_shop", args, tmp_path)
        assert sessions == [
            (BASE_URL, "s1"),
            (BASE_URL, "s2"),
            (BASE_URL, None),
            (BASE_URL, None),
        ]

    def test_dvwa_and_webgoat_are_the_logged_in_targets(self) -> None:
        assert set(runner.LOGIN) == {"dvwa", "webgoat"}
