"""Unit tests for EmailSender — SMTP dispatch and disabled-mode logging."""

import base64
import re
import smtplib
from unittest.mock import MagicMock, patch

import pytest

from src.auth.email import EmailSender, SMTPConfig

_B64_RE = re.compile(r"(?:[A-Za-z0-9+/]{4})+(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?")


def _decode_mime_body(raw_msg: str) -> str:
    """Decode all base64 chunks in a MIME wire-format string into plain text."""
    chunks = _B64_RE.findall(raw_msg)
    return " ".join(
        base64.b64decode(chunk).decode("utf-8", errors="ignore")
        for chunk in chunks
        if len(chunk) >= 4
    )


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _make_sender(*, enabled: bool = False, use_tls: bool = True) -> EmailSender:
    cfg = SMTPConfig(
        enabled=enabled,
        host="smtp.example.com",
        port=587,
        username="user@example.com",
        password="hunter2",
        use_tls=use_tls,
        from_address="noreply@haris.example.com",
        from_name="HARIS Test",
    )
    return EmailSender(cfg)


# ---------------------------------------------------------------------------
# send_verification_email — SMTP disabled
# ---------------------------------------------------------------------------


class TestSendVerificationEmailSmtpDisabled:
    def test_does_not_call_smtp_when_disabled(self):
        sender = _make_sender(enabled=False)
        with patch("src.auth.email.smtplib.SMTP") as mock_smtp:
            sender.send_verification_email(
                to_email="alice@example.com",
                token="tok123",
                base_url="https://haris.example.com",
            )
        mock_smtp.assert_not_called()

    def test_logs_verify_url_when_disabled(self, caplog):
        sender = _make_sender(enabled=False)
        import logging

        with caplog.at_level(logging.INFO, logger="src.auth.email"):
            sender.send_verification_email(
                to_email="alice@example.com",
                token="tok123",
                base_url="https://haris.example.com",
            )
        assert any("tok123" in record.message for record in caplog.records)

    def test_verify_url_in_log_contains_correct_path(self, caplog):
        sender = _make_sender(enabled=False)
        import logging

        with caplog.at_level(logging.INFO, logger="src.auth.email"):
            sender.send_verification_email(
                to_email="bob@example.com",
                token="mytoken",
                base_url="https://haris.example.com",
            )
        joined = " ".join(r.message for r in caplog.records)
        assert "/auth/verify-email?token=mytoken" in joined

    def test_trailing_slash_stripped_from_base_url(self, caplog):
        sender = _make_sender(enabled=False)
        import logging

        with caplog.at_level(logging.INFO, logger="src.auth.email"):
            sender.send_verification_email(
                to_email="carol@example.com",
                token="t99",
                base_url="https://haris.example.com/",
            )
        # Must not produce double-slash: //auth/verify-email
        joined = " ".join(r.message for r in caplog.records)
        assert "//auth/verify-email" not in joined
        assert "/auth/verify-email?token=t99" in joined


# ---------------------------------------------------------------------------
# send_verification_email — SMTP enabled
# ---------------------------------------------------------------------------


class TestSendVerificationEmailSmtpEnabled:
    def test_calls_smtp_with_correct_host_and_port(self):
        sender = _make_sender(enabled=True, use_tls=True)
        mock_smtp_instance = MagicMock()
        mock_smtp_instance.__enter__ = MagicMock(return_value=mock_smtp_instance)
        mock_smtp_instance.__exit__ = MagicMock(return_value=False)

        with patch(
            "src.auth.email.smtplib.SMTP",
            return_value=mock_smtp_instance,
        ) as mock_smtp_cls:
            sender.send_verification_email(
                to_email="dave@example.com",
                token="tok456",
                base_url="https://haris.example.com",
            )
        mock_smtp_cls.assert_called_once_with("smtp.example.com", 587)

    def test_starttls_called_when_use_tls_true(self):
        sender = _make_sender(enabled=True, use_tls=True)
        mock_smtp_instance = MagicMock()
        mock_smtp_instance.__enter__ = MagicMock(return_value=mock_smtp_instance)
        mock_smtp_instance.__exit__ = MagicMock(return_value=False)

        with patch("src.auth.email.smtplib.SMTP", return_value=mock_smtp_instance):
            sender.send_verification_email(
                to_email="eve@example.com",
                token="tok789",
                base_url="https://haris.example.com",
            )
        mock_smtp_instance.starttls.assert_called_once()

    def test_sendmail_called_with_correct_recipient(self):
        sender = _make_sender(enabled=True, use_tls=True)
        mock_smtp_instance = MagicMock()
        mock_smtp_instance.__enter__ = MagicMock(return_value=mock_smtp_instance)
        mock_smtp_instance.__exit__ = MagicMock(return_value=False)

        with patch("src.auth.email.smtplib.SMTP", return_value=mock_smtp_instance):
            sender.send_verification_email(
                to_email="frank@example.com",
                token="tokABC",
                base_url="https://haris.example.com",
            )
        call_args = mock_smtp_instance.sendmail.call_args
        assert call_args is not None
        # sendmail(from_addr, to_addrs, msg)
        _, to_addrs, _ = call_args[0]
        assert "frank@example.com" in to_addrs

    def test_email_body_contains_token_url(self):
        sender = _make_sender(enabled=True, use_tls=True)
        mock_smtp_instance = MagicMock()
        mock_smtp_instance.__enter__ = MagicMock(return_value=mock_smtp_instance)
        mock_smtp_instance.__exit__ = MagicMock(return_value=False)

        with patch("src.auth.email.smtplib.SMTP", return_value=mock_smtp_instance):
            sender.send_verification_email(
                to_email="grace@example.com",
                token="tok-verify",
                base_url="https://haris.example.com",
            )
        call_args = mock_smtp_instance.sendmail.call_args
        assert call_args is not None
        _, _, raw_msg = call_args[0]
        # MIMEMultipart encodes body parts as base64; decode before searching.
        assert "tok-verify" in _decode_mime_body(raw_msg)

    def test_login_called_when_username_set(self):
        sender = _make_sender(enabled=True, use_tls=True)
        mock_smtp_instance = MagicMock()
        mock_smtp_instance.__enter__ = MagicMock(return_value=mock_smtp_instance)
        mock_smtp_instance.__exit__ = MagicMock(return_value=False)

        with patch("src.auth.email.smtplib.SMTP", return_value=mock_smtp_instance):
            sender.send_verification_email(
                to_email="henry@example.com",
                token="tok-login",
                base_url="https://haris.example.com",
            )
        mock_smtp_instance.login.assert_called_once_with("user@example.com", "hunter2")

    def test_login_not_called_when_username_empty(self):
        cfg = SMTPConfig(
            enabled=True,
            host="smtp.example.com",
            port=587,
            username="",
            password="",
            use_tls=True,
        )
        sender = EmailSender(cfg)
        mock_smtp_instance = MagicMock()
        mock_smtp_instance.__enter__ = MagicMock(return_value=mock_smtp_instance)
        mock_smtp_instance.__exit__ = MagicMock(return_value=False)

        with patch("src.auth.email.smtplib.SMTP", return_value=mock_smtp_instance):
            sender.send_verification_email(
                to_email="iris@example.com",
                token="tok-nologin",
                base_url="https://haris.example.com",
            )
        mock_smtp_instance.login.assert_not_called()

    def test_smtp_exception_is_reraised(self):
        sender = _make_sender(enabled=True, use_tls=True)
        mock_smtp_instance = MagicMock()
        mock_smtp_instance.__enter__ = MagicMock(return_value=mock_smtp_instance)
        mock_smtp_instance.__exit__ = MagicMock(return_value=False)
        mock_smtp_instance.sendmail.side_effect = smtplib.SMTPException(
            "Connection refused",
        )

        with (
            patch("src.auth.email.smtplib.SMTP", return_value=mock_smtp_instance),
            pytest.raises(smtplib.SMTPException),
        ):
            sender.send_verification_email(
                to_email="jake@example.com",
                token="tok-fail",
                base_url="https://haris.example.com",
            )

    def test_no_tls_path_does_not_call_starttls(self):
        sender = _make_sender(enabled=True, use_tls=False)
        mock_smtp_instance = MagicMock()
        mock_smtp_instance.__enter__ = MagicMock(return_value=mock_smtp_instance)
        mock_smtp_instance.__exit__ = MagicMock(return_value=False)

        with patch("src.auth.email.smtplib.SMTP", return_value=mock_smtp_instance):
            sender.send_verification_email(
                to_email="kate@example.com",
                token="tok-notls",
                base_url="https://haris.example.com",
            )
        mock_smtp_instance.starttls.assert_not_called()
        mock_smtp_instance.sendmail.assert_called_once()


# ---------------------------------------------------------------------------
# send_password_reset_email — SMTP disabled
# ---------------------------------------------------------------------------


class TestSendPasswordResetEmailSmtpDisabled:
    def test_does_not_call_smtp_when_disabled(self):
        sender = _make_sender(enabled=False)
        with patch("src.auth.email.smtplib.SMTP") as mock_smtp:
            sender.send_password_reset_email(
                to_email="leo@example.com",
                token="reset-tok",
                base_url="https://haris.example.com",
            )
        mock_smtp.assert_not_called()

    def test_logs_reset_url_when_disabled(self, caplog):
        sender = _make_sender(enabled=False)
        import logging

        with caplog.at_level(logging.INFO, logger="src.auth.email"):
            sender.send_password_reset_email(
                to_email="leo@example.com",
                token="reset-tok",
                base_url="https://haris.example.com",
            )
        assert any("reset-tok" in record.message for record in caplog.records)

    def test_reset_url_in_log_contains_correct_path(self, caplog):
        sender = _make_sender(enabled=False)
        import logging

        with caplog.at_level(logging.INFO, logger="src.auth.email"):
            sender.send_password_reset_email(
                to_email="mia@example.com",
                token="rst99",
                base_url="https://haris.example.com",
            )
        joined = " ".join(r.message for r in caplog.records)
        assert "/auth/reset-password?token=rst99" in joined

    def test_reset_trailing_slash_stripped_from_base_url(self, caplog):
        sender = _make_sender(enabled=False)
        import logging

        with caplog.at_level(logging.INFO, logger="src.auth.email"):
            sender.send_password_reset_email(
                to_email="ned@example.com",
                token="rst-slash",
                base_url="https://haris.example.com/",
            )
        joined = " ".join(r.message for r in caplog.records)
        assert "//auth/reset-password" not in joined
        assert "/auth/reset-password?token=rst-slash" in joined


# ---------------------------------------------------------------------------
# send_password_reset_email — SMTP enabled
# ---------------------------------------------------------------------------


class TestSendPasswordResetEmailSmtpEnabled:
    def test_calls_smtp_when_enabled(self):
        sender = _make_sender(enabled=True, use_tls=True)
        mock_smtp_instance = MagicMock()
        mock_smtp_instance.__enter__ = MagicMock(return_value=mock_smtp_instance)
        mock_smtp_instance.__exit__ = MagicMock(return_value=False)

        with patch(
            "src.auth.email.smtplib.SMTP",
            return_value=mock_smtp_instance,
        ) as mock_smtp_cls:
            sender.send_password_reset_email(
                to_email="oscar@example.com",
                token="rst-tok",
                base_url="https://haris.example.com",
            )
        mock_smtp_cls.assert_called_once()

    def test_email_body_contains_reset_token(self):
        sender = _make_sender(enabled=True, use_tls=True)
        mock_smtp_instance = MagicMock()
        mock_smtp_instance.__enter__ = MagicMock(return_value=mock_smtp_instance)
        mock_smtp_instance.__exit__ = MagicMock(return_value=False)

        with patch("src.auth.email.smtplib.SMTP", return_value=mock_smtp_instance):
            sender.send_password_reset_email(
                to_email="pat@example.com",
                token="rst-bodycheck",
                base_url="https://haris.example.com",
            )
        call_args = mock_smtp_instance.sendmail.call_args
        assert call_args is not None
        _, _, raw_msg = call_args[0]
        # MIMEMultipart encodes body parts as base64; decode before searching.
        assert "rst-bodycheck" in _decode_mime_body(raw_msg)

    def test_smtp_exception_reraised_on_reset(self):
        sender = _make_sender(enabled=True, use_tls=True)
        mock_smtp_instance = MagicMock()
        mock_smtp_instance.__enter__ = MagicMock(return_value=mock_smtp_instance)
        mock_smtp_instance.__exit__ = MagicMock(return_value=False)
        mock_smtp_instance.sendmail.side_effect = smtplib.SMTPException(
            "Timeout",
        )

        with (
            patch("src.auth.email.smtplib.SMTP", return_value=mock_smtp_instance),
            pytest.raises(smtplib.SMTPException),
        ):
            sender.send_password_reset_email(
                to_email="quinn@example.com",
                token="rst-fail",
                base_url="https://haris.example.com",
            )


# ---------------------------------------------------------------------------
# SMTPConfig defaults
# ---------------------------------------------------------------------------


class TestSMTPConfigDefaults:
    def test_smtp_disabled_by_default(self):
        cfg = SMTPConfig()
        assert cfg.enabled is False

    def test_default_port_is_587(self):
        cfg = SMTPConfig()
        assert cfg.port == 587

    def test_default_use_tls_is_true(self):
        cfg = SMTPConfig()
        assert cfg.use_tls is True

    def test_default_host_is_localhost(self):
        cfg = SMTPConfig()
        assert cfg.host == "localhost"
