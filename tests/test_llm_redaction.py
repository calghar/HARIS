import pytest

from haris.llm.redaction import MASK, Redactor, redact
from haris.llm.settings import LLMSettings, RedactionSettings, load_settings
from tests.evals.fake_provider import FakeProvider

JWT = "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.dBjftJeZ4CVPmB92K27uhbUJU1p1r"
PRIVATE_KEY = (
    "-----BEGIN RSA PRIVATE KEY-----\nMIIEowIBAAKCAQEA7\n-----END RSA PRIVATE KEY-----"
)


class TestProviderBoundary:
    def test_secrets_are_masked_before_the_provider_sees_them(self):
        """Authorization, Cookie and sk- key all reach the provider masked."""
        provider = FakeProvider(lambda r: "ok")
        provider.complete(
            "GET /admin HTTP/1.1\n"
            "Authorization: Bearer abc\n"
            "Cookie: sid=sess-1a2b3c4d; theme=dark\n"
            "X-Debug: sk-proj-Zq81LmNpQr92XyTv\n",
            system="Authorization: Bearer sys-secret-9",
        )
        wire = provider.wire_text
        for secret in ("Bearer abc", "sess-1a2b3c4d", "sk-proj-Zq81", "sys-secret-9"):
            assert secret not in wire
        assert wire.count(MASK) >= 4

    def test_history_messages_are_masked_too(self):
        provider = FakeProvider(lambda r: "ok")
        provider.complete_messages(
            [
                {"role": "user", "content": "token=hunter2hunter2"},
                {"role": "assistant", "content": f"saw {JWT}"},
            ]
        )
        assert "hunter2hunter2" not in provider.wire_text
        assert JWT not in provider.wire_text


@pytest.mark.parametrize(
    "text,secret",
    [
        ("Authorization: Bearer abc", "abc"),
        ("proxy-authorization: Basic dXNlcjpwdw==", "dXNlcjpwdw"),
        ('"Authorization": "Bearer tok-xyz-1234"', "tok-xyz-1234"),
        ("Set-Cookie: JSESSIONID=ABCDEF123456; Path=/; HttpOnly", "ABCDEF123456"),
        ('{"cookie": "sid=zzz999yyy"}', "zzz999yyy"),
        (f"jwt in body {JWT}", JWT),
        ("use Bearer 8f9a7c6b5d4e3f2a1b", "8f9a7c6b5d4e3f2a1b"),
        ("key sk-ant-api03-AbCdEf123456", "AbCdEf123456"),
        ("aws AKIAIOSFODNN7EXAMPLE", "AKIAIOSFODNN7EXAMPLE"),
        ("gh ghp_abcdefghijklmnopqrstuvwxyz0123", "ghp_abcdefghijklmnopqrstuvwxyz0123"),
        ("api_key=Zx81Qw9917", "Zx81Qw9917"),
        ('{"password": "correct-horse"}', "correct-horse"),
        ("https://admin:s3cretpw@internal.example.com/x", "s3cretpw"),
        (f"leak {PRIVATE_KEY} end", "MIIEowIBAAKCAQEA7"),
    ],
)
def test_secret_shapes_are_masked(text, secret):
    assert secret not in redact(text)
    assert redact(redact(text)) == redact(text)


@pytest.mark.parametrize(
    "text",
    [
        "Missing Strict-Transport-Security header",
        "Cookie flags: missing Secure and HttpOnly",
        "risk-assessment-2024-final-report",
        "Authentication bypass via password reset flow",
    ],
)
def test_ordinary_prose_is_untouched(text):
    assert redact(text) == text


def test_emails_masked_only_when_configured():
    text = "contact admin@example.com"
    assert redact(text) == text
    cfg = load_settings().model_copy(
        update={"redaction": RedactionSettings(emails=True)}
    )
    assert Redactor(cfg).redact(text) == f"contact {MASK}"


def test_extra_patterns_apply_and_invalid_ones_are_rejected():
    cfg = load_settings().model_copy(
        update={"redaction": RedactionSettings(extra_patterns=[r"TENANT-\d+"])}
    )
    assert Redactor(cfg).redact("org TENANT-4411") == f"org {MASK}"
    with pytest.raises(ValueError):
        LLMSettings.model_validate(
            {
                "providers": {"x": {"default": "m"}},
                "redaction": {"extra_patterns": ["("]},
            }
        )
