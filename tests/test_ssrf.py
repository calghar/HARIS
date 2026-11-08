import ipaddress

import pytest

from haris.net import NetworkPolicy, SSRFBlocked
from haris.net.ssrf import embedded_ipv4, is_blocked, is_metadata, vet_addresses

from .fake_transport import FakeNet

PUBLIC_V4 = "93.184.216.34"
PUBLIC_V6 = "2606:2800:220:1:248:1893:25c8:1946"


@pytest.mark.parametrize(
    ("ip", "allow_private", "outcome"),
    [
        (PUBLIC_V4, False, "sent"),
        ("127.0.0.1", False, "SSRFBlocked"),
        ("127.0.0.1", True, "sent"),
        ("10.1.2.3", False, "SSRFBlocked"),
        ("172.16.0.1", False, "SSRFBlocked"),
        ("192.168.1.1", False, "SSRFBlocked"),
        ("100.64.0.1", False, "SSRFBlocked"),
        ("169.254.10.10", False, "SSRFBlocked"),
        ("169.254.169.254", True, "SSRFBlocked"),
        ("100.100.100.200", True, "SSRFBlocked"),
        ("0.0.0.0", False, "SSRFBlocked"),
        ("::1", False, "SSRFBlocked"),
        ("fe80::1", False, "SSRFBlocked"),
        ("fd12:3456::1", False, "SSRFBlocked"),
        ("fd00:ec2::254", True, "SSRFBlocked"),
        ("::ffff:127.0.0.1", False, "SSRFBlocked"),
        ("64:ff9b::a01:203", False, "SSRFBlocked"),
        ("2002:c0a8:101::1", False, "SSRFBlocked"),
        (PUBLIC_V6, False, "sent"),
        ("::ffff:169.254.169.254", True, "SSRFBlocked"),
        ("224.0.0.1", False, "SSRFBlocked"),
        ("192.0.2.1", False, "SSRFBlocked"),
        ("198.18.0.1", False, "SSRFBlocked"),
    ],
)
def test_address_class_matrix(ip, allow_private, outcome):
    """Scenario: Address class matrix."""
    net = FakeNet(
        base_url="https://t.example",
        resolves={"t.example": [ip]},
        allow_private=allow_private,
    )
    if outcome == "sent":
        assert net.client.get("https://t.example/").status_code == 200
        assert len(net.sent) == 1
    else:
        with pytest.raises(SSRFBlocked):
            net.client.get("https://t.example/")
        assert net.sent == []


def test_mixed_resolution_is_rejected():
    """Scenario: Mixed resolution is rejected."""
    net = FakeNet(
        base_url="https://t.example", resolves={"t.example": [PUBLIC_V4, "10.0.0.5"]}
    )
    with pytest.raises(SSRFBlocked, match="10.0.0.5"):
        net.client.get("https://t.example/")
    assert net.sent == []


def test_dns_rebinding_after_first_resolution_keeps_vetted_address():
    """Scenario: DNS rebinding after first resolution."""
    net = FakeNet(base_url="https://t.example", resolves={"t.example": [PUBLIC_V4]})
    net.client.get("https://t.example/")
    net.resolves["t.example"] = ["127.0.0.1"]
    net.client.get("https://t.example/x")

    assert net.resolver_calls == ["t.example"]
    assert [r.url for r in net.sent] == [
        f"https://{PUBLIC_V4}:443/",
        f"https://{PUBLIC_V4}:443/x",
    ]
    assert all(r.headers["Host"] == "t.example" for r in net.sent)


def test_blocked_result_is_cached_per_scan():
    net = FakeNet(base_url="https://t.example", resolves={"t.example": ["10.0.0.5"]})
    for _ in range(2):
        with pytest.raises(SSRFBlocked):
            net.client.get("https://t.example/")
    assert net.resolver_calls == ["t.example"]


def test_ip_literal_url_is_vetted_without_resolution():
    net = FakeNet(base_url="http://127.0.0.1:8080")
    with pytest.raises(SSRFBlocked):
        net.client.get("http://127.0.0.1:8080/")
    allowed = FakeNet(base_url="http://127.0.0.1:8080", allow_private=True)
    assert allowed.client.get("http://127.0.0.1:8080/").status_code == 200


def test_metadata_host_blocked_even_with_override():
    net = FakeNet(
        base_url="http://metadata.google.internal",
        resolves={"metadata.google.internal": [PUBLIC_V4]},
        allow_private=True,
    )
    with pytest.raises(SSRFBlocked, match="metadata"):
        net.client.get("http://metadata.google.internal/")


def test_error_message_names_the_override_flag():
    with pytest.raises(SSRFBlocked, match="--allow-private"):
        vet_addresses("t.example", ["10.0.0.1"], allow_private=False)


@pytest.mark.parametrize(
    ("source", "environ", "outcome"),
    [
        ("cli", None, "SSRFBlocked"),
        ("cli", "--allow-private", "sent"),
        ("web", {}, "SSRFBlocked"),
        ("web", {"HARIS_ALLOW_PRIVATE_TARGETS": "true"}, "sent"),
        ("web", {"HARIS_ALLOW_PRIVATE_TARGETS": "false"}, "SSRFBlocked"),
    ],
)
def test_override_sources(source, environ, outcome):
    """Scenario: Override sources (a web form field is never read)."""
    if source == "cli":
        policy = NetworkPolicy(allow_private=environ == "--allow-private")
    else:
        policy = NetworkPolicy.from_env(environ)
    net = FakeNet(
        base_url="https://t.example",
        resolves={"t.example": ["10.0.0.5"]},
        allow_private=policy.allow_private,
    )
    if outcome == "sent":
        assert net.client.get("https://t.example/").status_code == 200
    else:
        with pytest.raises(SSRFBlocked):
            net.client.get("https://t.example/")


def test_embedded_ipv4_extraction():
    assert embedded_ipv4(
        ipaddress.ip_address("64:ff9b::a01:203")
    ) == ipaddress.ip_address("10.1.2.3")
    assert embedded_ipv4(
        ipaddress.ip_address("2002:c0a8:101::1")
    ) == ipaddress.ip_address("192.168.1.1")
    assert embedded_ipv4(ipaddress.ip_address(PUBLIC_V6)) is None
    assert is_metadata(ipaddress.ip_address("::ffff:169.254.169.254"))
    assert not is_blocked(ipaddress.ip_address(PUBLIC_V4))
