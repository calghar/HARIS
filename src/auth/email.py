import logging
import smtplib
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText

from pydantic import BaseModel

logger = logging.getLogger(__name__)


class SMTPConfig(BaseModel):
    enabled: bool = False
    host: str = "localhost"
    port: int = 587
    username: str = ""
    password: str = ""
    use_tls: bool = True
    from_address: str = "noreply@techforpalestine.org"
    from_name: str = "HARIS Security Platform"


class EmailSender:
    def __init__(self, config: SMTPConfig) -> None:
        self._config = config

    def send_verification_email(self, to_email: str, token: str, base_url: str) -> None:
        verify_url = f"{base_url.rstrip('/')}/auth/verify-email?token={token}"
        subject = "Verify your HARIS account"
        html_body = f"""
<p>Welcome to HARIS!</p>
<p>Please verify your email address by clicking the link below:</p>
<p><a href="{verify_url}">{verify_url}</a></p>
<p>This link expires in 24 hours.</p>
<p>If you did not request this, please ignore this email.</p>
"""
        text_body = (
            f"Welcome to HARIS!\n\n"
            f"Please verify your email address by visiting:\n{verify_url}\n\n"
            f"This link expires in 24 hours.\n"
        )
        if not self._config.enabled:
            logger.info("Email verification link (SMTP disabled): %s", verify_url)
            return
        self._send(to_email, subject, html_body, text_body)

    def send_password_reset_email(
        self, to_email: str, token: str, base_url: str
    ) -> None:
        reset_url = f"{base_url.rstrip('/')}/auth/reset-password?token={token}"
        subject = "Reset your HARIS password"
        html_body = f"""
<p>A password reset was requested for your HARIS account.</p>
<p>Click the link below to set a new password:</p>
<p><a href="{reset_url}">{reset_url}</a></p>
<p>This link expires in 1 hour. If you did not request this, please
ignore this email.</p>
"""
        text_body = (
            f"A password reset was requested for your HARIS account.\n\n"
            f"Visit this link to set a new password:\n{reset_url}\n\n"
            f"This link expires in 1 hour.\n"
        )
        if not self._config.enabled:
            logger.info("Password reset link (SMTP disabled): %s", reset_url)
            return
        self._send(to_email, subject, html_body, text_body)

    def _send(self, to: str, subject: str, html_body: str, text_body: str) -> None:
        cfg = self._config
        msg = MIMEMultipart("alternative")
        msg["Subject"] = subject
        msg["From"] = f"{cfg.from_name} <{cfg.from_address}>"
        msg["To"] = to
        msg.attach(MIMEText(text_body, "plain", "utf-8"))
        msg.attach(MIMEText(html_body, "html", "utf-8"))
        try:
            if cfg.use_tls:
                with smtplib.SMTP(cfg.host, cfg.port) as smtp:
                    smtp.ehlo()
                    smtp.starttls()
                    if cfg.username:
                        smtp.login(cfg.username, cfg.password)
                    smtp.sendmail(cfg.from_address, [to], msg.as_string())
            else:
                with smtplib.SMTP(cfg.host, cfg.port) as smtp:
                    if cfg.username:
                        smtp.login(cfg.username, cfg.password)
                    smtp.sendmail(cfg.from_address, [to], msg.as_string())
            logger.debug("Email sent to %s: %s", to, subject)
        except smtplib.SMTPException as exc:
            logger.error("Failed to send email to %s: %s", to, exc)
            raise
