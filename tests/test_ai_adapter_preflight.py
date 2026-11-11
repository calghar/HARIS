import importlib
import os
from pathlib import Path
from typing import Any

import pytest
from requests.structures import CaseInsensitiveDict

from haris.ai_security.discovery import Endpoint
from haris.ai_security.signatures import Signature
from haris.models import ScanContext, ScannerResult, Target
from haris.net.transport import ScopedResponse
from haris.scanners.garak_scanner import GarakScanner
from haris.scanners.promptfoo_scanner import PromptfooScanner

from .adapter_support import BOTH, FAKE_GARAK, FAKE_PROMPTFOO, Tool, run
from .ai_support import net_with

SCANNERS = [GarakScanner, PromptfooScanner]
LOOPBACK = "http://127.0.0.1/v1/chat/completions"
PRIVATE = "http://10.1.2.3/v1/chat/completions"
METADATA = "http://169.254.169.254/latest/meta-data"
OUT_OF_SCOPE = "https://evil.test/v1/chat/completions"


class Bins:
    def __init__(self, root: Path) -> None:
        self.garak = Tool(root, "garak", FAKE_GARAK)
        self.promptfoo = Tool(root, "promptfoo", FAKE_PROMPTFOO)

    @property
    def calls(self) -> list[dict[str, Any]]:
        return self.garak.calls


@pytest.fixture
def bins(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Bins:
    installed = Bins(tmp_path)
    path = os.pathsep.join((str(installed.garak.bin), os.environ["PATH"]))
    monkeypatch.setenv("PATH", path)
    return installed


def _endpoint(url: str) -> Endpoint:
    return Endpoint(
        signature=Signature(
            id="chat",
            label="chat",
            path="/v1/models",
            validator="body",
            capability="chat",
            chat_path="/v1/chat/completions",
        ),
        url=url,
        response=ScopedResponse(
            status_code=200, url=url, headers=CaseInsensitiveDict()
        ),
        chat_url=url,
    )


def _install(monkeypatch: pytest.MonkeyPatch, scanner: Any, url: str) -> None:
    module = importlib.import_module(scanner.__module__)

    def _chat(_target: Target, _context: ScanContext | None) -> Endpoint:
        return _endpoint(url)

    monkeypatch.setattr(module, "chat_endpoint", _chat)


def _scan(scanner: Any, *, base_url: str, allow_private: bool) -> ScannerResult:
    net = net_with({}, base_url=base_url, allow_private=allow_private)
    result: ScannerResult = scanner(dict(BOTH)).scan(
        net.client.target, ScanContext(http=net.client)
    )
    return result


@pytest.mark.parametrize("scanner", SCANNERS)
def test_out_of_scope_endpoint_is_refused(
    bins: Bins, monkeypatch: pytest.MonkeyPatch, scanner: Any
) -> None:
    _install(monkeypatch, scanner, OUT_OF_SCOPE)
    result = _scan(scanner, base_url="https://example.com", allow_private=False)
    assert result.findings == []
    assert "outside the authorised scope" in result.errors[0]
    assert bins.calls == []


@pytest.mark.parametrize("scanner", SCANNERS)
@pytest.mark.parametrize("url", [LOOPBACK, PRIVATE])
def test_private_endpoint_is_refused_without_allow_private(
    bins: Bins, monkeypatch: pytest.MonkeyPatch, scanner: Any, url: str
) -> None:
    _install(monkeypatch, scanner, url)
    result = _scan(scanner, base_url=url, allow_private=False)
    assert result.findings == []
    assert "blocked address" in result.errors[0]
    assert bins.calls == []


@pytest.mark.parametrize("scanner", SCANNERS)
@pytest.mark.parametrize("url", [LOOPBACK, PRIVATE])
def test_private_endpoint_is_accepted_with_allow_private(
    bins: Bins, monkeypatch: pytest.MonkeyPatch, scanner: Any, url: str
) -> None:
    _install(monkeypatch, scanner, url)
    result = _scan(scanner, base_url=url, allow_private=True)
    assert result.errors == []
    assert bins.calls
    argv = bins.calls[0]["argv"]
    if scanner is GarakScanner:
        assert argv[1:3] == ["--target_type", "rest"]
    else:
        assert argv[1:3] == ["redteam", "generate"]


@pytest.mark.parametrize("scanner", SCANNERS)
def test_metadata_address_is_refused_with_allow_private(
    bins: Bins, monkeypatch: pytest.MonkeyPatch, scanner: Any
) -> None:
    _install(monkeypatch, scanner, METADATA)
    result = _scan(scanner, base_url=METADATA, allow_private=True)
    assert result.findings == []
    assert "blocked address" in result.errors[0]
    assert bins.calls == []


@pytest.mark.parametrize("scanner", SCANNERS)
def test_post_method_must_be_allowed(
    bins: Bins, monkeypatch: pytest.MonkeyPatch, scanner: Any
) -> None:
    url = "https://example.com/v1/chat/completions"
    _install(monkeypatch, scanner, url)
    net = net_with({}, post=False)
    result = scanner(dict(BOTH)).scan(net.client.target, ScanContext(http=net.client))
    assert result.findings == []
    assert "method POST" in result.errors[0]
    assert bins.calls == []


def test_accepted_garak_endpoint_keeps_argv(bins: Bins) -> None:
    result = run(GarakScanner, **BOTH)
    argv = bins.calls[0]["argv"][1:]
    assert argv[:4] == ["--target_type", "rest", "-G", argv[3]]
    assert argv[argv.index("--parallel_attempts") + 1] == "1"
    assert result.errors == []


def test_accepted_promptfoo_endpoint_keeps_argv(bins: Bins) -> None:
    result = run(PromptfooScanner, **BOTH)
    generate, evaluate = bins.calls
    assert generate["argv"][1:3] == ["redteam", "generate"]
    assert evaluate["argv"][1] == "eval"
    assert "--no-share" in evaluate["argv"] and "--no-write" in evaluate["argv"]
    assert evaluate["argv"][evaluate["argv"].index("--max-concurrency") + 1] == "1"
    assert result.errors == []
