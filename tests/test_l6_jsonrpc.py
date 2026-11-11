import importlib

import pytest


def test_l6_jsonrpc_module_is_not_importable() -> None:
    with pytest.raises(ModuleNotFoundError):
        importlib.import_module("haris.ai_security.jsonrpc")
