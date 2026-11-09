import hashlib
import json
import re
from collections.abc import Iterator
from dataclasses import dataclass
from typing import Any

from ..models import Finding
from .discovery import Endpoint
from .findings import ai_finding
from .signatures import McpRules, load_signatures

# U+E0000-E007F, U+200B-200D, U+2060, U+202A-202E, U+2066-2069
HIDDEN_RANGES = (
    (0xE0000, 0xE007F),
    (0x200B, 0x200D),
    (0x2060, 0x2060),
    (0x202A, 0x202E),
    (0x2066, 0x2069),
)
SNIPPET_CHARS = 80
MAX_CODEPOINTS = 8
STRING_TYPE = "string"
CONSTRAINTS = ("enum", "pattern", "const")
CAMEL_BOUNDARY = re.compile(r"(?<=[a-z0-9])(?=[A-Z])")
WORDS = re.compile(r"[a-z]+")


@dataclass(frozen=True)
class Definition:
    """A tool, resource or prompt the server advertised."""

    surface: str
    body: dict[str, Any]

    @property
    def name(self) -> str:
        return str(self.body.get("name", ""))

    @property
    def digest(self) -> str:
        canonical = json.dumps(self.body, sort_keys=True, default=str)
        return hashlib.sha256(canonical.encode()).hexdigest()[:16]


def _texts(node: Any) -> Iterator[str]:
    """Every name and description string in a definition, schemas included."""
    if isinstance(node, dict):
        for key, value in node.items():
            if key in ("name", "description", "title") and isinstance(value, str):
                yield value
            elif isinstance(value, dict | list):
                yield from _texts(value)
    elif isinstance(node, list):
        for item in node:
            yield from _texts(item)


def _hidden(text: str) -> list[str]:
    return [
        f"U+{ord(ch):04X}"
        for ch in text
        if any(lo <= ord(ch) <= hi for lo, hi in HIDDEN_RANGES)
    ]


def _free_form(schema: Any, rules: McpRules, path: str = "") -> Iterator[str]:
    """Dotted names of string parameters that are free-form and unconstrained."""
    if not isinstance(schema, dict):
        return
    for name, prop in (schema.get("properties") or {}).items():
        if not isinstance(prop, dict):
            continue
        dotted = f"{path}{name}"
        kind = prop.get("type")
        is_string = kind == STRING_TYPE or (
            isinstance(kind, list) and STRING_TYPE in kind
        )
        if (
            name.lower() in rules.free_form_params
            and is_string
            and not any(c in prop for c in CONSTRAINTS)
        ):
            yield dotted
        yield from _free_form(prop, rules, f"{dotted}.")
    yield from _free_form(schema.get("items"), rules, path)


def _words(name: str) -> set[str]:
    return set(WORDS.findall(CAMEL_BOUNDARY.sub("_", name).lower()))


def toxic_pair(tools: list[Definition], rules: McpRules) -> list[str]:
    """Names of private-data readers and senders when both kinds exist, else empty."""
    readers = {
        t.name
        for t in tools
        if (w := _words(t.name)) & set(rules.read_verbs)
        and w & set(rules.private_nouns)
    }
    senders = {t.name for t in tools if _words(t.name) & set(rules.send_verbs)}
    if any(r != s for r in readers for s in senders):
        return sorted(readers | senders)
    return []


def _first_instruction(texts: list[str], patterns: list[re.Pattern[str]]) -> str:
    """A short snippet around the first instruction-like phrase, or empty."""
    for text in texts:
        hit = next((m for p in patterns if (m := p.search(text))), None)
        if hit:
            return " ".join(text[max(0, hit.start() - 10) :].split())[:SNIPPET_CHARS]
    return ""


def static_findings(endpoint: Endpoint, definitions: list[Definition]) -> list[Finding]:
    rules = load_signatures().mcp
    patterns = [re.compile(p) for p in rules.instruction_patterns]
    found: list[Finding] = []

    def add(
        kind: str, item: Definition, detail: str, evidence: str, parameter: str = ""
    ) -> None:
        found.append(
            ai_finding(
                kind,
                url=endpoint.url,
                method=endpoint.signature.method,
                parameter=parameter or item.name,
                detail=detail,
                evidence=evidence,
                digest=item.digest,
            )
        )

    for item in definitions:
        texts = list(_texts(item.body))
        label = f"{item.surface} {item.name}"
        if snippet := _first_instruction(texts, patterns):
            add(
                "tool_description_injection", item, f'In {label}: "{snippet}".', snippet
            )
        codepoints = sorted({cp for text in texts for cp in _hidden(text)})
        if codepoints:
            shown = ", ".join(codepoints[:MAX_CODEPOINTS])
            add("hidden_unicode", item, f"In {label}: {shown}.", shown)
        if item.surface == "tool":
            for param in _free_form(item.body.get("inputSchema"), rules):
                add(
                    "excessive_agency_schema",
                    item,
                    f"Tool {item.name} parameter {param}.",
                    f"{item.name}({param}: string)",
                    f"{item.name}.{param}",
                )
    pair = toxic_pair([d for d in definitions if d.surface == "tool"], rules)
    if pair:
        names = ", ".join(pair)
        found.append(
            ai_finding(
                "toxic_flow",
                url=endpoint.url,
                method=endpoint.signature.method,
                detail=f"Tools: {names}.",
                evidence=names,
                digest=hashlib.sha256(names.encode()).hexdigest()[:16],
            )
        )
    return found
