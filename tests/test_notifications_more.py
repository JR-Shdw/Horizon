"""Extra tests for api/app/routes/notifications.py.

Targets: _send_notification (unknown channel), dispatch_event (try/except),
_send_email (recipient parsing, missing host), _smtp_send_sync (mock SMTP).
"""

import ssl
from email.message import EmailMessage
from unittest.mock import MagicMock, patch

import pytest
from api.app.routes.notifications import (
    _send_email,
    _send_matrix,
    _send_notification,
    _smtp_send_sync,
    dispatch_event,
)

# ---------------------------------------------------------------------------
# _send_notification : unknown channel
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_send_notification_unknown_channel_type(caplog):
    """unknown channel_type -> log warning, no exception."""
    with caplog.at_level("WARNING"):
        await _send_notification("teletype", {}, "event", "msg")
    assert any("Unknown channel type" in r.message for r in caplog.records)


# ---------------------------------------------------------------------------
# dispatch_event : try/except around _send_notification
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_dispatch_event_swallows_send_failures(monkeypatch):
    """An exception in _send_notification is caught and logged."""
    from api.app.database import async_session
    from sqlalchemy import text as _text

    # Insert an enabled "matrix" channel but with invalid config
    async with async_session() as db:
        await db.execute(
            _text("""
                INSERT INTO vault_notification_channels
                    (name, channel_type, config, enabled)
                VALUES (:n, 'matrix', '{}'::jsonb, true)
                ON CONFLICT (name) DO UPDATE SET enabled = true
            """),
            {"n": "test-channel-dispatch-fail"},
        )
        await db.commit()

    # Patch _send_notification so it raises
    from api.app.routes import notifications as mod

    async def boom(*a, **kw):
        raise RuntimeError("simulated send error")

    monkeypatch.setattr(mod, "_send_notification", boom)

    # dispatch_event must NOT raise
    async with async_session() as db:
        await dispatch_event(db, "test_event", "test message")

    # Cleanup
    async with async_session() as db:
        await db.execute(
            _text("DELETE FROM vault_notification_channels WHERE name = :n"),
            {"n": "test-channel-dispatch-fail"},
        )
        await db.commit()


@pytest.mark.asyncio
async def test_dispatch_event_filters_by_event_subscription():
    """A channel with events=[A] does not receive event B."""
    from api.app.database import async_session
    from sqlalchemy import text as _text

    async with async_session() as db:
        # Subscription lives in the `events` COLUMN (what create_channel writes),
        # not inside config -- this is the contract dispatch_event must read.
        await db.execute(
            _text("""
                INSERT INTO vault_notification_channels
                    (name, channel_type, config, events, enabled)
                VALUES (:n, 'matrix', '{}'::jsonb, '["unseal"]'::jsonb, true)
                ON CONFLICT (name) DO UPDATE
                    SET config = '{}'::jsonb,
                        events = '["unseal"]'::jsonb,
                        enabled = true
            """),
            {"n": "test-channel-event-filter"},
        )
        await db.commit()

    # Patch to verify it is NOT called
    from api.app.routes import notifications as mod

    called = []

    async def fake_send(channel_type, cfg, event, msg):
        called.append((channel_type, event))

    with patch.object(mod, "_send_notification", fake_send):
        async with async_session() as db:
            await dispatch_event(db, "seal", "test")  # event 'seal' not listed

    assert called == []  # filtered out

    # Cleanup
    async with async_session() as db:
        await db.execute(
            _text("DELETE FROM vault_notification_channels WHERE name = :n"),
            {"n": "test-channel-event-filter"},
        )
        await db.commit()


@pytest.mark.asyncio
async def test_dispatch_event_delivers_subscribed_event():
    """A channel subscribed (events column) to event A receives event A."""
    from api.app.database import async_session
    from sqlalchemy import text as _text

    async with async_session() as db:
        await db.execute(
            _text("""
                INSERT INTO vault_notification_channels
                    (name, channel_type, config, events, enabled)
                VALUES (:n, 'matrix', '{}'::jsonb, '["seal"]'::jsonb, true)
                ON CONFLICT (name) DO UPDATE
                    SET config = '{}'::jsonb, events = '["seal"]'::jsonb,
                        enabled = true
            """),
            {"n": "test-channel-event-deliver"},
        )
        await db.commit()

    from api.app.routes import notifications as mod

    called = []

    async def fake_send(channel_type, cfg, event, msg):
        called.append(event)

    with patch.object(mod, "_send_notification", fake_send):
        async with async_session() as db:
            await dispatch_event(db, "seal", "test")  # subscribed -> delivered

    assert called == ["seal"]

    async with async_session() as db:
        await db.execute(
            _text("DELETE FROM vault_notification_channels WHERE name = :n"),
            {"n": "test-channel-event-deliver"},
        )
        await db.commit()


@pytest.mark.asyncio
async def test_send_matrix_ssrf_blocked():
    """A Matrix homeserver pointing at a cloud-metadata host is rejected."""
    with pytest.raises(ValueError, match="SSRF"):
        await _send_matrix(
            {
                "homeserver": "http://169.254.169.254",
                "room_id": "!x:y",
                "token": "t",
            },
            "test",
            "msg",
        )


@pytest.mark.asyncio
async def test_send_email_ssrf_blocked():
    """An SMTP host that resolves to loopback is rejected before connecting."""
    with pytest.raises(ValueError, match="SSRF"):
        await _send_email(
            {"smtp_host": "127.0.0.1", "to": ["ops@example.com"]}, "test", "msg"
        )


# ---------------------------------------------------------------------------
# _send_email : recipient parsing + host validation
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_send_email_missing_host_raises():
    with pytest.raises(ValueError, match="smtp_host"):
        await _send_email({}, "event", "message")


@pytest.mark.asyncio
async def test_send_email_no_recipients_raises():
    with pytest.raises(ValueError, match="smtp_host"):
        await _send_email({"smtp_host": "mail.example.com"}, "event", "msg")


@pytest.mark.asyncio
async def test_send_email_string_recipients_parsed(monkeypatch):
    """`to` as a CSV string -> parsed into a list."""
    captured = []

    def fake_send_sync(host, port, use_ssl, use_starttls, user, pwd, msg):
        captured.append((host, port, msg["To"]))

    from api.app.routes import notifications as mod

    monkeypatch.setattr(mod, "_smtp_send_sync", fake_send_sync)

    await _send_email(
        {
            "smtp_host": "mail.example.com",
            "to": "a@x.com, b@x.com ,c@x.com",
        },
        "event",
        "message",
    )

    assert captured
    host, port, to = captured[0]
    assert host == "mail.example.com"
    assert "a@x.com" in to and "b@x.com" in to and "c@x.com" in to


# ---------------------------------------------------------------------------
# _smtp_send_sync : mock smtplib
# ---------------------------------------------------------------------------


def test_smtp_send_sync_starttls(monkeypatch):
    """STARTTLS path: ehlo -> starttls -> ehlo -> login -> send -> quit."""
    fake_client = MagicMock()
    smtp_class = MagicMock(return_value=fake_client)

    monkeypatch.setattr("api.app.routes.notifications._PinnedSMTP", smtp_class)

    msg = EmailMessage()
    msg["Subject"] = "x"
    msg["From"] = "a@b"
    msg["To"] = "c@d"
    msg.set_content("body")

    _smtp_send_sync(
        "mail.example.com",
        587,
        use_ssl=False,
        use_starttls=True,
        user="me",
        password="pw",
        msg=msg,
    )

    smtp_class.assert_called_once()
    fake_client.starttls.assert_called_once()
    fake_client.login.assert_called_once_with("me", "pw")
    fake_client.send_message.assert_called_once()
    fake_client.quit.assert_called_once()


def test_smtp_send_sync_ssl_no_login(monkeypatch):
    """SSL path, no login: SMTP_SSL -> ehlo -> send -> quit (no starttls/login)."""
    fake_client = MagicMock()
    ssl_class = MagicMock(return_value=fake_client)

    monkeypatch.setattr("api.app.routes.notifications._PinnedSMTPSSL", ssl_class)

    msg = EmailMessage()
    msg["Subject"] = "x"
    msg["From"] = "a@b"
    msg["To"] = "c@d"
    msg.set_content("body")

    _smtp_send_sync(
        "mail.example.com",
        465,
        use_ssl=True,
        use_starttls=False,
        user="",
        password="",
        msg=msg,
    )

    ssl_class.assert_called_once()
    fake_client.starttls.assert_not_called()
    fake_client.login.assert_not_called()
    fake_client.send_message.assert_called_once()


def test_smtp_send_sync_quit_failure_falls_back_to_close(monkeypatch):
    """If quit() raises, fall back to close()."""
    fake_client = MagicMock()
    fake_client.quit.side_effect = RuntimeError("connection broken")
    smtp_class = MagicMock(return_value=fake_client)

    monkeypatch.setattr("api.app.routes.notifications._PinnedSMTP", smtp_class)

    msg = EmailMessage()
    msg["Subject"] = "x"
    msg["From"] = "a@b"
    msg["To"] = "c@d"
    msg.set_content("body")

    _smtp_send_sync(
        "mail.example.com",
        25,
        use_ssl=False,
        use_starttls=False,
        user="",
        password="",
        msg=msg,
    )

    fake_client.close.assert_called_once()


def _smtp_message() -> EmailMessage:
    msg = EmailMessage()
    msg["Subject"] = "x"
    msg["From"] = "a@b"
    msg["To"] = "c@d"
    msg.set_content("body")
    return msg


def _verifying(context) -> bool:
    return context.verify_mode == ssl.CERT_REQUIRED and context.check_hostname


def test_smtp_starttls_verifies_the_server_certificate(monkeypatch):
    fake_client = MagicMock()
    monkeypatch.setattr(
        "api.app.routes.notifications._PinnedSMTP", MagicMock(return_value=fake_client)
    )
    _smtp_send_sync("mail.example.com", 587, False, True, "me", "pw", _smtp_message())
    assert _verifying(fake_client.starttls.call_args.kwargs["context"])


def test_smtp_ssl_verifies_the_server_certificate(monkeypatch):
    ssl_class = MagicMock(return_value=MagicMock())
    monkeypatch.setattr("api.app.routes.notifications._PinnedSMTPSSL", ssl_class)
    _smtp_send_sync("mail.example.com", 465, True, False, "me", "pw", _smtp_message())
    assert _verifying(ssl_class.call_args.kwargs["context"])


def test_smtp_credentials_are_refused_without_tls(monkeypatch):
    smtp_class = MagicMock()
    monkeypatch.setattr("api.app.routes.notifications._PinnedSMTP", smtp_class)
    with pytest.raises(ValueError, match="require TLS"):
        _smtp_send_sync(
            "mail.example.com", 25, False, False, "me", "pw", _smtp_message()
        )
    smtp_class.assert_not_called()


def _addresses(*ips):
    return [(2, 1, 6, "", (ip, 0)) for ip in ips]


def test_pinned_address_rejects_any_internal_answer(monkeypatch):
    from api.app.routes import notifications as n

    monkeypatch.setattr(
        n.socket, "getaddrinfo", lambda *a, **k: _addresses("8.8.8.8", "10.0.0.1")
    )
    with pytest.raises(ValueError, match="SSRF"):
        n._pinned_address("rebind.example", 443)


def test_pinned_address_rejects_ipv4_mapped_loopback(monkeypatch):
    from api.app.routes import notifications as n

    monkeypatch.setattr(
        n.socket, "getaddrinfo", lambda *a, **k: _addresses("::ffff:127.0.0.1")
    )
    with pytest.raises(ValueError, match="SSRF"):
        n._pinned_address("rebind.example", 443)


@pytest.mark.asyncio
async def test_rebinding_after_the_early_check_never_connects(monkeypatch):
    """The name is public for the guard, then internal for the connection."""
    from api.app.routes import notifications as n

    answers = iter(["8.8.8.8", "127.0.0.1"])
    monkeypatch.setattr(
        n.socket, "getaddrinfo", lambda *a, **k: _addresses(next(answers))
    )
    connected = []

    class Recorder:
        async def connect_tcp(self, host, port, **kwargs):
            connected.append(host)
            raise AssertionError("must not connect")

    monkeypatch.setattr(n.httpcore, "AnyIOBackend", Recorder)
    with pytest.raises(ValueError, match="SSRF"):
        await n._send_webhook({"url": "http://rebind.example/hook"}, "e", "m")
    assert connected == []


@pytest.mark.asyncio
async def test_backend_connects_to_the_validated_address(monkeypatch):
    from api.app.routes import notifications as n

    monkeypatch.setattr(n.socket, "getaddrinfo", lambda *a, **k: _addresses("8.8.8.8"))
    seen = {}

    class Recorder:
        async def connect_tcp(self, host, port, **kwargs):
            seen["host"] = host
            return "stream"

    monkeypatch.setattr(n.httpcore, "AnyIOBackend", Recorder)
    assert await n._PinnedBackend().connect_tcp("hook.example", 443) == "stream"
    assert seen["host"] == "8.8.8.8"


def test_smtp_socket_connects_to_the_validated_address(monkeypatch):
    from api.app.routes import notifications as n

    monkeypatch.setattr(n.socket, "getaddrinfo", lambda *a, **k: _addresses("8.8.8.8"))
    seen = {}

    def fake_get_socket(self, host, port, timeout):
        seen["host"] = host
        return "socket"

    monkeypatch.setattr(n.smtplib.SMTP, "_get_socket", fake_get_socket)
    client = n._PinnedSMTP()
    assert client._get_socket("mail.example", 25, 5) == "socket"
    assert seen["host"] == "8.8.8.8"
