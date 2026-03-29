"""System-owned outbound email service.

Supports both:
1. Platform-level configuration via environment variables
2. Tenant-level configuration via system_settings table
"""

from __future__ import annotations

import asyncio
import inspect
import logging
import smtplib
import ssl
import uuid
from collections.abc import Iterable
from dataclasses import dataclass
from datetime import datetime
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
from email.utils import formataddr, make_msgid

from app.config import get_settings
from app.core.email import force_ipv4, send_smtp_email

logger = logging.getLogger(__name__)


class SystemEmailConfigError(RuntimeError):
    """Raised when system email configuration is missing or invalid."""


@dataclass(slots=True)
class SystemEmailConfig:
    """Resolved system email configuration."""

    from_address: str
    from_name: str
    smtp_host: str
    smtp_port: int
    smtp_username: str
    smtp_password: str
    smtp_ssl: bool
    smtp_timeout_seconds: int


@dataclass(slots=True)
class BroadcastEmailRecipient:
    """Prepared broadcast recipient payload."""

    email: str
    subject: str
    body: str


async def get_tenant_email_config(db, tenant_id: uuid.UUID | None = None) -> SystemEmailConfig | None:
    """Get email configuration from system_settings for a tenant.

    Args:
        db: Database session
        tenant_id: Tenant ID (if None, uses environment variable config)

    Returns:
        SystemEmailConfig if configured, None otherwise
    """
    if not tenant_id:
        return None

    try:
        from sqlalchemy import select
        from app.models.system_settings import SystemSetting

        config_key = f"system_email_{tenant_id}"
        result = await db.execute(select(SystemSetting).where(SystemSetting.key == config_key))
        setting = result.scalar_one_or_none()

        if not setting or not setting.value:
            return None

        value = setting.value
        from_address = str(value.get("SYSTEM_EMAIL_FROM_ADDRESS", "")).strip()
        smtp_host = str(value.get("SYSTEM_SMTP_HOST", "")).strip()
        smtp_password = str(value.get("SYSTEM_SMTP_PASSWORD", ""))

        # Return None if required fields are missing
        if not from_address or not smtp_host or not smtp_password:
            return None

        return SystemEmailConfig(
            from_address=from_address,
            from_name=str(value.get("SYSTEM_EMAIL_FROM_NAME", "Clawith")).strip() or "Clawith",
            smtp_host=smtp_host,
            smtp_port=int(value.get("SYSTEM_SMTP_PORT", 465)),
            smtp_username=str(value.get("SYSTEM_SMTP_USERNAME", "")).strip() or from_address,
            smtp_password=smtp_password,
            smtp_ssl=bool(value.get("SYSTEM_SMTP_SSL", True)),
            smtp_timeout_seconds=max(1, int(value.get("SYSTEM_SMTP_TIMEOUT_SECONDS", 15))),
        )
    except Exception as e:
        logger.warning(f"Failed to load tenant email config: {e}")
        return None


def get_system_email_config() -> SystemEmailConfig:
    """Get platform-level fallback email configuration from system_settings ('platform' key).

    This is used when tenant doesn't have its own email configuration.
    Falls back to environment variables for backward compatibility.
    """
    # Try to get from system_settings first (for platform-level config)
    try:
        import asyncio
        from sqlalchemy import select
        from app.database import async_session
        from app.models.system_settings import SystemSetting

        async def _fetch_platform_config():
            async with async_session() as db:
                result = await db.execute(select(SystemSetting).where(SystemSetting.key == "system_email_platform"))
                setting = result.scalar_one_or_none()
                if setting and setting.value:
                    value = setting.value
                    from_address = str(value.get("SYSTEM_EMAIL_FROM_ADDRESS", "")).strip()
                    smtp_host = str(value.get("SYSTEM_SMTP_HOST", "")).strip()
                    smtp_password = str(value.get("SYSTEM_SMTP_PASSWORD", ""))
                    if from_address and smtp_host and smtp_password:
                        return SystemEmailConfig(
                            from_address=from_address,
                            from_name=str(value.get("SYSTEM_EMAIL_FROM_NAME", "Clawith")).strip() or "Clawith",
                            smtp_host=smtp_host,
                            smtp_port=int(value.get("SYSTEM_SMTP_PORT", 465)),
                            smtp_username=str(value.get("SYSTEM_SMTP_USERNAME", "")).strip() or from_address,
                            smtp_password=smtp_password,
                            smtp_ssl=bool(value.get("SYSTEM_SMTP_SSL", True)),
                            smtp_timeout_seconds=max(1, int(value.get("SYSTEM_SMTP_TIMEOUT_SECONDS", 15))),
                        )
                return None

        config = asyncio.get_event_loop().run_until_complete(_fetch_platform_config())
        if config:
            return config
    except Exception:
        pass

    # Fallback to environment variables for backward compatibility
    from app.config import get_settings
    settings = get_settings()
    from_address = getattr(settings, 'SYSTEM_EMAIL_FROM_ADDRESS', '').strip()
    smtp_host = getattr(settings, 'SYSTEM_SMTP_HOST', '').strip()
    smtp_username = getattr(settings, 'SYSTEM_SMTP_USERNAME', '').strip() or from_address
    smtp_password = getattr(settings, 'SYSTEM_SMTP_PASSWORD', '')
    smtp_port = getattr(settings, 'SYSTEM_SMTP_PORT', 465)
    smtp_ssl = getattr(settings, 'SYSTEM_SMTP_SSL', True)
    smtp_timeout = getattr(settings, 'SYSTEM_SMTP_TIMEOUT_SECONDS', 15)

    if not from_address or not smtp_host or not smtp_password:
        raise SystemEmailConfigError(
            "System email is not configured. Configure email settings in Enterprise Settings or set environment variables."
        )

    return SystemEmailConfig(
        from_address=from_address,
        from_name=getattr(settings, 'SYSTEM_EMAIL_FROM_NAME', 'Clawith').strip() or "Clawith",
        smtp_host=smtp_host,
        smtp_port=smtp_port,
        smtp_username=smtp_username,
        smtp_password=smtp_password,
        smtp_ssl=smtp_ssl,
        smtp_timeout_seconds=max(1, int(smtp_timeout)),
    )


async def send_system_email(to: str, subject: str, body: str, tenant_id: uuid.UUID | None = None, db=None) -> None:
    """Send a plain-text system email without blocking the event loop.

    Args:
        to: Recipient email address
        subject: Email subject
        body: Email body text
        tenant_id: Optional tenant ID to use tenant-specific config
        db: Optional database session (required if tenant_id is provided)
    """
    # Try tenant-level config first
    config = None
    if tenant_id and db:
        config = await get_tenant_email_config(db, tenant_id)

    # Fallback to platform-level env config
    if not config:
        try:
            config = get_system_email_config()
        except SystemEmailConfigError:
            logger.warning("System email not configured (neither tenant nor platform level)")
            return

    await asyncio.to_thread(_send_email_with_config_sync, config, to, subject, body)


def _send_email_with_config_sync(config: SystemEmailConfig, to: str, subject: str, body: str) -> None:
    """Send email with provided config."""
    msg = MIMEMultipart()
    msg["From"] = formataddr((config.from_name, config.from_address))
    msg["To"] = to
    msg["Subject"] = subject
    msg["Message-ID"] = make_msgid()
    msg["Date"] = datetime.now().strftime("%a, %d %b %Y %H:%M:%S %z")
    msg.attach(MIMEText(body, "plain", "utf-8"))

    send_smtp_email(
        host=config.smtp_host,
        port=config.smtp_port,
        user=config.smtp_username,
        password=config.smtp_password,
        from_addr=config.from_address,
        to_addrs=[to],
        msg_string=msg.as_string(),
        use_ssl=config.smtp_ssl,
        timeout=config.smtp_timeout_seconds,
    )


async def send_password_reset_email(
    to: str,
    display_name: str,
    reset_url: str,
    expiry_minutes: int,
    tenant_id: uuid.UUID | None = None,
    db=None,
) -> None:
    """Send a password reset email.

    Args:
        to: Recipient email
        display_name: User display name
        reset_url: Password reset URL
        expiry_minutes: Token expiry time in minutes
        tenant_id: Optional tenant ID for tenant-specific email config
        db: Optional database session
    """
    subject = "Reset your Clawith password"
    body = (
        f"Hello {display_name},\n\n"
        f"We received a request to reset your Clawith password.\n\n"
        f"Reset link: {reset_url}\n\n"
        f"This link expires in {expiry_minutes} minutes. If you did not request this, you can ignore this email."
    )
    await send_system_email(to, subject, body, tenant_id=tenant_id, db=db)


async def deliver_broadcast_emails(recipients: Iterable[BroadcastEmailRecipient]) -> None:
    """Deliver broadcast emails while isolating per-recipient failures."""
    for recipient in recipients:
        try:
            await send_system_email(recipient.email, recipient.subject, recipient.body)
        except Exception as exc:
            logger.warning("Failed to deliver broadcast email to %s: %s", recipient.email, exc)


def fire_and_forget(coro) -> None:
    """Run an awaitable in the background without failing the request."""
    task = asyncio.create_task(coro)

    def _consume_task_result(done_task: asyncio.Task) -> None:
        try:
            done_task.result()
        except Exception as exc:
            logger.warning("Background email task failed: %s", exc)

    task.add_done_callback(_consume_task_result)


def run_background_email_job(job, *args, **kwargs) -> None:
    """Bridge Starlette background tasks to async email jobs."""
    result = job(*args, **kwargs)
    if inspect.isawaitable(result):
        fire_and_forget(result)
