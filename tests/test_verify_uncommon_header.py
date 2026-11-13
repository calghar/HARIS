from urllib.parse import urlsplit

import pytest
import requests

from haris.models import VerificationTier
from haris.verify.oracles_baseline import control_url
from haris.verify.replay import replay
from tests.checks_support import Route, site
from tests.fake_transport import Reply
from tests.verify_server import case, fast_settings

T = VerificationTier
HEADER = {"Content-Disposition": "inline;filename=f.txt"}
TITLE = (
    "Uncommon header(s) 'content-disposition' found, "
    "with contents: inline;filename=f.txt."
)
PATH = "/WebGoat/trace.axd"


def header_by_extension(request: requests.PreparedRequest) -> Reply:
    """Like Spring's reflected-download guard: the header follows the extension."""
    path = urlsplit(request.url or "").path
    return 404, HEADER if path.endswith(".axd") else {}, b"{}"


@pytest.mark.parametrize(
    ("title", "routes", "fallback", "tier", "roles"),
    [
        (TITLE, {}, header_by_extension, T.REFUTED, ["probe", "control"]),
        (
            TITLE,
            {PATH: (404, HEADER, b"{}")},
            (404, {}, b"{}"),
            T.UNVERIFIED,
            ["probe", "control"],
        ),
        (
            TITLE,
            {PATH: (404, HEADER, b"{}")},
            (404, {"Content-Disposition": "attachment"}, b"{}"),
            T.UNVERIFIED,
            ["probe", "control"],
        ),
        (
            "This might be interesting.",
            {},
            (404, HEADER, b"{}"),
            T.UNVERIFIED,
            ["probe"],
        ),
    ],
    ids=[
        "header-on-control",
        "header-only-on-probe",
        "header-value-differs",
        "other-finding-class",
    ],
)
def test_uncommon_header_is_refuted_only_when_the_control_carries_it(
    title: str,
    routes: dict[str, Route],
    fallback: Route,
    tier: VerificationTier,
    roles: list[str],
) -> None:
    """Scenario: Header on the control path."""
    net = site(routes, fallback=fallback)
    finding = case(title, f"https://example.com{PATH}", scanner="nikto", parameter="")
    replay([finding], net.client, fast_settings())
    verification = finding.canonical.verification
    assert verification.tier == tier
    assert [e.role for e in verification.evidence] == roles
    assert len(net.sent) == len(roles)


@pytest.mark.parametrize(
    ("url", "directory", "extension"),
    [
        ("https://example.com/WebGoat/trace.axd?x=1#f", "/WebGoat/", ".axd"),
        ("https://example.com/a/b", "/a/", ""),
        ("https://example.com/dir/", "/dir/", ""),
    ],
)
def test_control_url_keeps_the_directory_and_extension(
    url: str, directory: str, extension: str
) -> None:
    built = urlsplit(control_url("https://example.com", url))
    assert built.path.startswith(f"{directory}haris-")
    assert built.path.endswith(extension)
    assert not built.query
    assert not built.fragment
