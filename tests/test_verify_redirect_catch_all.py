import pytest

from haris.models import Scope, VerificationMethod, VerificationTier
from haris.verify.replay import replay
from tests.checks_support import site
from tests.verify_server import case, fast_settings

T = VerificationTier
type Reply = tuple[int, dict[str, str], bytes]

LOGIN: Reply = (302, {"Location": "/login"}, b"")
NOT_FOUND: Reply = (404, {}, b"not found")


@pytest.mark.parametrize(
    ("path", "probe", "tier"),
    [
        ("/.git/config", LOGIN, T.REFUTED),
        ("/admin", LOGIN, T.REFUTED),
        ("/admin", (302, {"Location": "/admin/index.html"}, b""), T.UNVERIFIED),
        ("/.git/config", NOT_FOUND, T.UNVERIFIED),
    ],
    ids=["git-config-to-login", "admin-to-login", "admin-to-index", "git-config-404"],
)
def test_replayed_external_finding_follows_the_redirect_controls(
    path: str, probe: Reply, tier: VerificationTier
) -> None:
    """Scenario: Redirect controls."""
    net = site(
        {path: probe},
        fallback=LOGIN,
        scope=Scope(rate_limit_rps=1000.0, follow_redirects=False),
    )
    finding = case(
        "This might be interesting.",
        f"https://example.com{path}",
        scanner="nikto",
        parameter="",
    )
    replay([finding], net.client, fast_settings())
    verification = finding.canonical.verification
    assert verification.tier == tier
    assert verification.method == VerificationMethod.REPLAY
