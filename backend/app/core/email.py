"""Core email utilities for SMTP operations and network compatibility."""

import socket
import ssl
import smtplib
from contextlib import contextmanager
from email.mime.multipart import MIMEMultipart
from typing import Optional


def _ipv4_getaddrinfo(host, port, family=0, type=0, proto=0, flags=0):
    """Wrapper that forces AF_INET (IPv4) to avoid IPv6 failures in Docker."""
    return _original_getaddrinfo(host, port, socket.AF_INET, type, proto, flags)


_original_getaddrinfo = socket.getaddrinfo


@contextmanager
def force_ipv4():
    """Context manager that forces all socket connections to use IPv4.

    Docker containers often lack IPv6 support, causing [Errno 99] when
    Python picks an AAAA record. This patches socket.getaddrinfo to only
    return IPv4 results while preserving the original hostname for SSL
    certificate verification (SNI).
    """
    socket.getaddrinfo = _ipv4_getaddrinfo
    try:
        yield
    finally:
        socket.getaddrinfo = _original_getaddrinfo


def send_smtp_email(
    host: str,
    port: int,
    user: str,
    password: str,
    from_addr: str,
    to_addrs: list[str],
    msg_string: str,
    use_ssl: bool = True,
    timeout: int = 15,
) -> None:
    """Synchronously send an email via SMTP with IPv4 enforcement.

    Args:
        host: SMTP server host
        port: SMTP server port
        user: SMTP username
        password: SMTP password/auth-code
        from_addr: Sender email address
        to_addrs: List of recipient email addresses
        msg_string: The full MIME message as a string
        use_ssl: Whether to use SMTP_SSL (True) or STARTTLS (False)
        timeout: Socket timeout in seconds
    """
    with force_ipv4():
        if use_ssl:
            context = ssl.create_default_context()
            with smtplib.SMTP_SSL(host, port, context=context, timeout=timeout) as server:
                server.login(user, password)
                server.sendmail(from_addr, to_addrs, msg_string)
        else:
            with smtplib.SMTP(host, port, timeout=timeout) as server:
                server.ehlo()
                if port == 587 or port == 25:  # Common STARTTLS ports
                    server.starttls(context=ssl.create_default_context())
                    server.ehlo()
                server.login(user, password)
                server.sendmail(from_addr, to_addrs, msg_string)
