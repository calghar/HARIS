import base64
import secrets
import shlex
from itertools import pairwise
from urllib.parse import unquote, urljoin

from ..models import Finding
from ..net import ScopedResponse
from .oracles import (
    INERT_HTML,
    MARKER_TAG,
    OracleResult,
    is_html,
    pair_result,
)
from .probe import CURL_MULTIPART_FLAGS, Prober, random_token
from .settings import VerifySettings

# true, false and the control
BOOLEAN_PER_ROUND = 3


def stored_multipart(finding: Finding) -> bool:
    try:
        tokens = shlex.split(finding.request_example)
    except ValueError:
        return False
    return bool(CURL_MULTIPART_FLAGS.intersection(tokens))


def data_wrapped(finding: Finding) -> bool:
    """The stored request asked the target to include a data: URI."""
    return "data:" in unquote(finding.request_example)


def chain_active(names: list[str], finding: Finding) -> list[str]:
    """Class chain plus the oracles this stored request can actually run."""
    extra: list[str] = []
    if stored_multipart(finding) and "file_marker" not in names:
        extra.append("file_marker")
    if "timing_cmd" in names and "code_eval" not in names and data_wrapped(finding):
        extra.append("code_eval")
    return names + extra


def _parts(finding: Finding) -> list[tuple[str, str]]:
    try:
        tokens = shlex.split(finding.request_example)
    except ValueError:
        return []
    return [
        (name, value)
        for flag, arg in pairwise(tokens)
        if flag in CURL_MULTIPART_FLAGS
        for name, sep, value in [arg.partition("=")]
        if sep
    ]


def _file_body(
    parts: list[tuple[str, str]], parameter: str, marker: str, boundary: str
) -> bytes:
    chunks: list[bytes] = []
    for name, value in parts:
        if name == parameter or value.startswith("@"):
            continue
        chunks.append(
            (
                f"--{boundary}\r\n"
                f'Content-Disposition: form-data; name="{name}"\r\n\r\n'
                f"{value}\r\n"
            ).encode()
        )
    chunks.append(
        (
            f"--{boundary}\r\n"
            f'Content-Disposition: form-data; name="{parameter}"; '
            f'filename="{marker}"\r\n'
            f"Content-Type: application/octet-stream\r\n\r\n"
        ).encode()
        + marker.encode()
        + b"\r\n"
    )
    chunks.append(f"--{boundary}--\r\n".encode())
    return b"".join(chunks)


def _send_file(prober: Prober, finding: Finding, marker: str) -> ScopedResponse:
    boundary = secrets.token_hex(8)
    url = urljoin(f"{prober.client.target.base_url}/", finding.url)
    body = _file_body(_parts(finding), finding.parameter, marker, boundary)
    headers = {"Content-Type": f"multipart/form-data; boundary={boundary}"}
    return prober.request(finding.method.upper(), url, body=body, headers=headers)


def file_marker(
    finding: Finding, prober: Prober, settings: VerifySettings
) -> OracleResult:
    """A marker file for a stored multipart request. Writes that file on the target."""
    if not finding.parameter or not stored_multipart(finding):
        return OracleResult(outcome="inconclusive", exchanges=[])
    marker = f"<{MARKER_TAG}{secrets.token_hex(4)}>"
    probe = _send_file(prober, finding, marker)
    control = _send_file(prober, finding, random_token(len(marker)))
    live = marker in INERT_HTML.sub("", probe.text)
    positive = is_html(probe) and live and marker not in control.text
    return pair_result(
        prober, "positive" if positive else "inconclusive", probe, control, marker
    )


def _php_payload(settings: VerifySettings) -> tuple[str, str]:
    left, right = secrets.token_hex(4), secrets.token_hex(4)
    marker = left + right
    php = settings.code_eval_template.format(left=left, right=right)
    payload = settings.code_eval_wrapper.format(
        b64=base64.b64encode(php.encode()).decode()
    )
    return marker, payload


def code_eval(
    finding: Finding, prober: Prober, settings: VerifySettings
) -> OracleResult:
    """PHP echo of a random marker, only after a stored data: wrapper."""
    if not data_wrapped(finding):
        return OracleResult(outcome="inconclusive", exchanges=[])
    marker, payload = _php_payload(settings)
    probe = prober.send(finding, payload)
    control = prober.send(finding, random_token(len(payload)))
    positive = (
        marker not in payload and marker in probe.text and marker not in control.text
    )
    return pair_result(
        prober, "positive" if positive else "inconclusive", probe, control, marker
    )


def _boolean_values(settings: VerifySettings) -> tuple[str, str, str]:
    probe_prefix = secrets.token_hex(4)
    control_prefix = secrets.token_hex(4)
    return (
        settings.boolean_true.format(prefix=probe_prefix),
        settings.boolean_false.format(prefix=probe_prefix),
        settings.boolean_control.format(prefix=control_prefix),
    )


def _stripped(response: ScopedResponse, value: str) -> tuple[int, str]:
    return response.status_code, response.text.replace(value, "")


def _boolean_round(
    true_r: ScopedResponse,
    false_r: ScopedResponse,
    control_r: ScopedResponse,
    true_v: str,
    false_v: str,
    control_v: str,
) -> bool:
    same = _stripped(true_r, true_v) == _stripped(control_r, control_v)
    differs = _stripped(false_r, false_v) != _stripped(control_r, control_v)
    return same and differs


def boolean_sqli(
    finding: Finding, prober: Prober, settings: VerifySettings
) -> OracleResult:
    """True matches the control and false differs, on every repeat."""
    sent: list[tuple[ScopedResponse, str, str]] = []
    agreed: list[bool] = []
    for _ in range(settings.boolean_repeats):
        true_v, false_v, control_v = _boolean_values(settings)
        true_r = prober.send(finding, true_v)
        false_r = prober.send(finding, false_v)
        control_r = prober.send(finding, control_v)
        sent += [
            (true_r, "probe", true_v),
            (false_r, "probe", false_v),
            (control_r, "control", ""),
        ]
        agreed.append(
            _boolean_round(true_r, false_r, control_r, true_v, false_v, control_v)
        )
    return OracleResult(
        outcome="positive" if agreed and all(agreed) else "inconclusive",
        exchanges=[prober.exchange(resp, role, span) for resp, role, span in sent],
        baseline_ref=sent[-1][0].request_id if sent else "",
    )
