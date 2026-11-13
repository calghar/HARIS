import json
import re
from typing import Any

from pydantic import BaseModel, ValidationError

ENVELOPE_KEY = "items"

_FENCE = re.compile(r"```[a-zA-Z0-9_-]*\s*\n(.*?)```", re.DOTALL)


class ParseResult[T: BaseModel](BaseModel):
    items: list[T]
    errors: list[str]
    raw: str = ""

    @property
    def ok(self) -> bool:
        return not self.errors


def extract_json(text: str) -> Any:
    """Return the first JSON value in text, bare or inside a markdown fence."""
    decoder = json.JSONDecoder()
    candidates = [text, *_FENCE.findall(text)]
    for candidate in candidates:
        try:
            return json.loads(candidate.strip())
        except json.JSONDecodeError:
            pass
    for match in re.finditer(r"[\[{]", text):
        try:
            return decoder.raw_decode(text[match.start() :])[0]
        except json.JSONDecodeError:
            continue
    raise ValueError("no JSON value in model output")


def _describe(exc: ValidationError) -> str:
    err = exc.errors()[0]
    where = ".".join(str(p) for p in err["loc"]) or "<root>"
    return f"{where}: {err['msg']}"


def parse_items[T: BaseModel](text: str, model: type[T]) -> ParseResult[T]:
    """Validate elements one by one; a bad element is dropped, not the batch."""
    try:
        data = extract_json(text)
    except ValueError as exc:
        return ParseResult(items=[], errors=[str(exc)])
    if isinstance(data, dict) and isinstance(data.get(ENVELOPE_KEY), list):
        data = data[ENVELOPE_KEY]
    if not isinstance(data, list):
        return ParseResult(items=[], errors=["expected a JSON array"])
    items: list[T] = []
    errors: list[str] = []
    for index, element in enumerate(data):
        try:
            items.append(model.model_validate(element))
        except ValidationError as exc:
            errors.append(f"item {index}: {_describe(exc)}")
    return ParseResult(items=items, errors=errors)


def parse_object[T: BaseModel](text: str, model: type[T]) -> ParseResult[T]:
    try:
        data = extract_json(text)
    except ValueError as exc:
        return ParseResult(items=[], errors=[str(exc)], raw=text)
    try:
        return ParseResult(items=[model.model_validate(data)], errors=[], raw=text)
    except ValidationError as exc:
        return ParseResult(items=[], errors=[_describe(exc)], raw=text)


def array_schema(model: type[BaseModel]) -> dict[str, Any]:
    """JSON schema for a provider-side structured request; roots must be objects."""
    return {
        "type": "object",
        "properties": {
            ENVELOPE_KEY: {"type": "array", "items": model.model_json_schema()}
        },
        "required": [ENVELOPE_KEY],
        "additionalProperties": False,
    }
