import ast
import ipaddress
import re
from collections.abc import Mapping
from re import Pattern
from typing import NamedTuple
from urllib.parse import urlsplit

from pydantic import BaseModel

from ..models import Scope
from ..net.ssrf import METADATA_HOSTS, is_metadata

ALLOWED_TOOLS = frozenset(
    {"http_request", "run_python", "write_file", "read_file", "submit_poc"}
)
ALLOWED_BINARIES = frozenset({"python3", "curl"})
_URL = re.compile(r"https?://[^\s'\"<>]+")
_BANNED_MODULES = frozenset({"subprocess", "socket", "pty", "ctypes"})
_OS_EXEC = frozenset({"system", "popen"})


class DenyRule(NamedTuple):
    id: str
    pattern: Pattern[str]


def _rule(rule_id: str, pattern: str) -> DenyRule:
    return DenyRule(rule_id, re.compile(pattern, re.IGNORECASE))


# Each id is part of the contract: dropping one must fail the guardrail test.
DENY_RULES: tuple[DenyRule, ...] = (
    _rule("command_subst", r"\$\("),
    _rule("backticks", r"`[^`\n]+`"),
    _rule("dollar_brace", r"\$\{"),
    _rule("base64_d_pipe", r"base64\s+-d\b"),
    _rule("base64_decode_flag", r"base64\s+--decode\b"),
    _rule("pipe_sh", r"\|\s*sh\b"),
    _rule("pipe_bash", r"\|\s*bash\b"),
    _rule("pipe_python", r"\|\s*python"),
    _rule(
        "b64decode_exec",
        r"b64decode\s*\([\s\S]{0,160}(?:exec|system|popen)"
        r"|(?:exec|system|popen)\s*\([\s\S]{0,160}b64decode",
    ),
    _rule(
        "fromhex_exec",
        r"fromhex\s*\([\s\S]{0,160}exec|exec\s*\([\s\S]{0,160}fromhex",
    ),
    _rule("eval_call", r"\beval\b"),
    _rule("exec_call", r"\bexec\s*\("),
    _rule("curl_pipe", r"\bcurl\b[^\n]*\|"),
    _rule("dev_tcp", r"/dev/tcp/"),
    _rule("nc_e", r"\bnc\s+[^\n]{0,40}-e\b"),
    _rule("ncat", r"\bncat\b"),
    _rule("socat", r"\bsocat\b"),
    _rule("bash_i", r"\bbash\s+-i\b"),
    _rule("metadata_aws", r"169\.254\.169\.254"),
    _rule("metadata_gcp", r"metadata\.google\.internal"),
    _rule("metadata_alicloud", r"100\.100\.100\.200"),
    _rule("metadata_ipv6", r"fd00:ec2::254"),
    _rule("pip_install", r"\bpip3?\s+install\b"),
    _rule("apt_install", r"\bapt(-get)?\s+install\b"),
    _rule("npm_install", r"\bnpm\s+install\b"),
    _rule("rm_rf", r"\brm\s+-rf\b"),
    _rule("mkfs", r"\bmkfs(\.\w+)?\b"),
    _rule("dd_of", r"\bdd\s+if="),
    _rule("shutdown", r"\bshutdown\b"),
    _rule("fork_bomb", r":\(\)\s*\{"),
    _rule("dotdot", r"\.\./"),
    _rule("docker_sock", r"docker\.sock"),
)


class GuardrailHit(BaseModel):
    reason: str
    rule: str


def _metadata(host: str) -> bool:
    if host.lower() in METADATA_HOSTS:
        return True
    try:
        return is_metadata(ipaddress.ip_address(host))
    except ValueError:
        return False


def _host_allowed(url: str, allowed_hosts: set[str]) -> bool:
    host = (urlsplit(url).hostname or "").lower()
    if not host or _metadata(host):
        return False
    return Scope(allowed_domains=sorted(allowed_hosts)).is_url_in_scope(url)


def in_work(path: str) -> bool:
    """True when *path* is a file under ``/work`` and does not escape it."""
    if not path or "\x00" in path or path.startswith("~"):
        return False
    parts = path.split("/")
    if ".." in parts:
        return False
    return path == "/work" or path.startswith("/work/")


def _argv_ok(command: str) -> bool:
    token = command.strip().split()
    return bool(token) and token[0] in ALLOWED_BINARIES


def _call_name(node: ast.AST) -> str:
    if isinstance(node, ast.Name):
        return node.id
    if isinstance(node, ast.Attribute) and isinstance(node.value, ast.Name):
        return f"{node.value.id}.{node.attr}"
    return ""


def python_reject_reason(script: str) -> str:
    """Static reject reason for a ``run_python`` script, or ``""`` when it is safe."""
    if not script.strip():
        return "empty"
    try:
        tree = ast.parse(script)
    except SyntaxError:
        return "syntax"
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for alias in node.names:
                if alias.name.split(".")[0] in _BANNED_MODULES:
                    return f"import {alias.name.split('.')[0]}"
        elif isinstance(node, ast.ImportFrom):
            root = (node.module or "").split(".")[0]
            names = {alias.name for alias in node.names}
            if root in _BANNED_MODULES or (root == "os" and names & _OS_EXEC):
                return f"import {root}"
        elif isinstance(node, ast.Call):
            name = _call_name(node.func)
            if name in {"exec", "eval", "compile", "__import__"}:
                return name
            if name in {"os.system", "os.popen"} or name.startswith("os.exec"):
                return name
    return ""


def screen(
    tool: str,
    arguments: Mapping[str, str],
    *,
    allowed_hosts: set[str],
) -> GuardrailHit | None:
    """Allow-listed tools only; then the denylist, scope, paths and Python AST."""
    if tool not in ALLOWED_TOOLS:
        return GuardrailHit(reason="tool", rule="allow-list")
    blob = "\n".join(arguments.values())
    for rule in DENY_RULES:
        if rule.pattern.search(blob):
            return GuardrailHit(reason="denylist", rule=rule.id)
    if tool != "submit_poc":
        for url in _URL.findall(blob):
            if not _host_allowed(url, allowed_hosts):
                return GuardrailHit(reason="scope", rule=urlsplit(url).hostname or "")
    if tool in {"write_file", "read_file"} and not in_work(arguments.get("path", "")):
        return GuardrailHit(reason="path", rule="work")
    command = arguments.get("command") or arguments.get("argv")
    if command is not None and not _argv_ok(command):
        return GuardrailHit(reason="argv", rule="allow-list")
    if tool == "run_python" and (
        reason := python_reject_reason(arguments.get("script", ""))
    ):
        return GuardrailHit(reason="python", rule=reason)
    method = arguments.get("method", "GET").upper()
    if tool == "http_request" and method not in {"GET", "HEAD", "OPTIONS", "POST"}:
        return GuardrailHit(reason="method", rule=method)
    return None
