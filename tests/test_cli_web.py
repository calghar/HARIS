from typing import Any

import pytest

from haris.cli import main


@pytest.mark.parametrize(("flags", "proxy"), [([], False), (["--proxy-headers"], True)])
def test_web_flag_serves_the_app_factory(
    monkeypatch: pytest.MonkeyPatch, flags: list[str], proxy: bool
) -> None:
    served: dict[str, Any] = {}
    built = object()
    monkeypatch.setattr("haris.web.app.create_app", lambda: built)
    monkeypatch.setattr(
        "uvicorn.run", lambda app, **kwargs: served.update(app=app, **kwargs)
    )
    assert main(["--web", "--port", "9001", *flags]) == 0
    assert served == {
        "app": built,
        "host": "127.0.0.1",
        "port": 9001,
        "proxy_headers": proxy,
    }
