import json
import re
from collections.abc import Callable
from typing import Any, cast

from ..checks.requesting import media_type
from ..net import ScopedResponse
from .rpc import EVENT_STREAM, parse_rpc

VLLM_OWNER = "vllm"
ENDPOINT_EVENT = re.compile(r"^event:\s*endpoint\s*$", re.MULTILINE)
NAME_KEYS = ("id", "name", "model")

type Validator = Callable[[ScopedResponse], bool]


def _json(resp: ScopedResponse) -> Any:
    try:
        return json.loads(resp.text)
    except ValueError:
        return None


def _object(resp: ScopedResponse) -> dict[str, Any]:
    body = _json(resp)
    return body if isinstance(body, dict) else {}


def _dicts_with(items: Any, key: str) -> bool:
    """*items* is a list whose entries all carry a non-empty *key*."""
    return isinstance(items, list) and all(
        isinstance(item, dict) and item.get(key) for item in items
    )


def _openai_list(resp: ScopedResponse) -> list[dict[str, Any]] | None:
    body = _object(resp)
    data = body.get("data")
    if body.get("object") == "list" and _dicts_with(data, "id"):
        return cast(list[dict[str, Any]], data)
    return None


def openai_models(resp: ScopedResponse) -> bool:
    data = _openai_list(resp)
    return data is not None and not any(m.get("owned_by") == VLLM_OWNER for m in data)


def vllm_models(resp: ScopedResponse) -> bool:
    data = _openai_list(resp)
    return data is not None and any(m.get("owned_by") == VLLM_OWNER for m in data)


def ollama_tags(resp: ScopedResponse) -> bool:
    models = _object(resp).get("models")
    return isinstance(models, list) and all(
        isinstance(m, dict) and (m.get("name") or m.get("model")) for m in models
    )


def tgi_info(resp: ScopedResponse) -> bool:
    body = _object(resp)
    return bool(body.get("model_id")) and (
        "max_input_tokens" in body or "max_total_tokens" in body
    )


def triton_metadata(resp: ScopedResponse) -> bool:
    body = _object(resp)
    return isinstance(body.get("name"), str) and isinstance(
        body.get("extensions"), list
    )


def langserve_docs(resp: ScopedResponse) -> bool:
    return "LangServe" in resp.text


def flowise_chatflows(resp: ScopedResponse) -> bool:
    body = _json(resp)
    return (
        isinstance(body, list)
        and bool(body)
        and any(isinstance(f, dict) and "flowData" in f for f in body)
    )


def open_webui_config(resp: ScopedResponse) -> bool:
    body = _object(resp)
    return "Open WebUI" in str(body.get("name", "")) and "features" in body


def gradio_config(resp: ScopedResponse) -> bool:
    body = _object(resp)
    return bool(body.get("version")) and isinstance(body.get("components"), list)


def mlflow_experiments(resp: ScopedResponse) -> bool:
    return isinstance(_object(resp).get("experiments"), list)


def ray_version(resp: ScopedResponse) -> bool:
    return isinstance(_object(resp).get("ray_version"), str)


def comfyui_stats(resp: ScopedResponse) -> bool:
    body = _object(resp)
    return isinstance(body.get("system"), dict) and isinstance(
        body.get("devices"), list
    )


def jupyter_kernels(resp: ScopedResponse) -> bool:
    return _dicts_with(_json(resp), "id")


def mcp_initialize(resp: ScopedResponse) -> bool:
    message = parse_rpc(resp)
    result = message.get("result") if message else None
    return (
        isinstance(result, dict)
        and bool(result.get("protocolVersion"))
        and isinstance(result.get("serverInfo"), dict)
    )


def mcp_sse_endpoint(resp: ScopedResponse) -> bool:
    return media_type(resp) == EVENT_STREAM and bool(ENDPOINT_EVENT.search(resp.text))


def oauth_resource(resp: ScopedResponse) -> bool:
    body = _object(resp)
    return bool(body.get("resource")) and isinstance(
        body.get("authorization_servers"), list
    )


VALIDATORS: dict[str, Validator] = {
    fn.__name__: fn
    for fn in (
        openai_models,
        vllm_models,
        ollama_tags,
        tgi_info,
        triton_metadata,
        langserve_docs,
        flowise_chatflows,
        open_webui_config,
        gradio_config,
        mlflow_experiments,
        ray_version,
        comfyui_stats,
        jupyter_kernels,
        mcp_initialize,
        mcp_sse_endpoint,
        oauth_resource,
    )
}


def model_names(resp: ScopedResponse) -> list[str]:
    """Model ids from an OpenAI, Ollama or TGI listing (empty when none)."""
    body = _json(resp)
    if isinstance(body, dict) and isinstance(body.get("model_id"), str):
        return [body["model_id"]]
    items = body.get("data") or body.get("models") if isinstance(body, dict) else None
    if not isinstance(items, list):
        return []
    names = (
        next((str(item[key]) for key in NAME_KEYS if item.get(key)), "")
        for item in items
        if isinstance(item, dict)
    )
    return [name for name in names if name]
