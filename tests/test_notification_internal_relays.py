"""Operators can list internal relays, and only exactly what they listed."""

import http.server
import ipaddress
import socket
import threading

import pytest
from api.app.config import Settings, parse_notify_internal_allow, settings
from api.app.routes import notifications as mod
from pydantic import ValidationError


class Hook(http.server.BaseHTTPRequestHandler):
    def log_message(self, *_args):
        pass

    def answer(self):
        length = int(self.headers.get("Content-Length", 0))
        self.server.seen.append(
            (self.command, self.path, self.headers.get("Authorization"))
        )
        self.rfile.read(length)
        self.send_response(200)
        self.send_header("Content-Length", "0")
        self.end_headers()

    do_POST = answer  # noqa: N815 - stdlib API
    do_PUT = answer  # noqa: N815 - stdlib API


@pytest.fixture
def http_port():
    server = http.server.ThreadingHTTPServer(("127.0.0.1", 0), Hook)
    server.seen = []
    threading.Thread(target=server.serve_forever, daemon=True).start()
    yield server
    server.shutdown()
    server.server_close()


@pytest.fixture
def smtp_relay():
    """Plain SMTP relay with login and no STARTTLS."""
    listener = socket.create_server(("127.0.0.1", 0))
    seen = []

    def run():
        while True:
            try:
                connection, _ = listener.accept()
            except OSError:
                return
            with connection:
                connection.sendall(b"220 relay ESMTP\r\n")
                stream = connection.makefile("rb")
                in_data = False
                while line := stream.readline():
                    seen.append(line)
                    if in_data:
                        if line == b".\r\n":
                            in_data = False
                            connection.sendall(b"250 queued\r\n")
                        continue
                    command = line[:4].upper()
                    if command == b"EHLO":
                        connection.sendall(b"250-relay\r\n250 AUTH PLAIN\r\n")
                    elif command == b"AUTH":
                        connection.sendall(b"235 ok\r\n")
                    elif command == b"DATA":
                        in_data = True
                        connection.sendall(b"354 go\r\n")
                    elif command == b"QUIT":
                        connection.sendall(b"221 bye\r\n")
                        break
                    else:
                        connection.sendall(b"250 ok\r\n")

    threading.Thread(target=run, daemon=True).start()
    yield listener.getsockname()[1], seen
    listener.close()


def allow(monkeypatch, value):
    monkeypatch.setattr(settings, "notify_internal_allow", value)


def email(port, **extra):
    return {
        "smtp_host": "127.0.0.1",
        "smtp_port": port,
        "smtp_use_starttls": False,
        "from": "vault@example.com",
        "to": ["ops@example.com"],
        **extra,
    }


@pytest.mark.parametrize(
    "value, count",
    [
        ("", 0),
        ("127.0.0.1", 1),
        ("127.0.0.1:25, 192.168.10.1/24, 10.0.0.0/8:8008", 3),
    ],
)
def test_accepted_entries(value, count):
    assert len(parse_notify_internal_allow(value)) == count


@pytest.mark.parametrize(
    "value",
    [
        "0.0.0.0/0",
        "0.0.0.0",
        "8.8.8.8",
        "1.1.1.0/24:25",
        "169.254.169.254",
        "169.254.0.0/16",
        "100.100.100.200",
        "127.0.0.1:0",
        "127.0.0.1:70000",
        "127.0.0.1:smtp",
        "relay.example",
    ],
)
def test_wide_or_public_entries_are_rejected_at_startup(value):
    with pytest.raises(ValueError):
        parse_notify_internal_allow(value)
    with pytest.raises(ValidationError):
        Settings(notify_internal_allow=value)


@pytest.mark.asyncio
async def test_loopback_stays_refused_by_default(monkeypatch, http_port):
    allow(monkeypatch, "")
    port = http_port.server_address[1]
    with pytest.raises(mod.DestinationRejected):
        await mod._send_webhook({"url": f"http://127.0.0.1:{port}/x"}, "e", "m")
    assert http_port.seen == []


@pytest.mark.asyncio
async def test_listed_matrix_relay_works_over_plain_http(monkeypatch, http_port):
    port = http_port.server_address[1]
    allow(monkeypatch, f"127.0.0.1:{port}")
    await mod._send_matrix(
        {
            "homeserver": f"http://127.0.0.1:{port}",
            "room_id": "!room",
            "token": "bot-token",
        },
        "seal",
        "m",
    )
    method, path, authorization = http_port.seen[0]
    assert method == "PUT"
    assert "!room" in path
    assert authorization == "Bearer bot-token"


@pytest.mark.asyncio
async def test_listed_host_with_a_port_opens_only_that_port(monkeypatch, http_port):
    port = http_port.server_address[1]
    allow(monkeypatch, f"127.0.0.1:{port + 1}")
    with pytest.raises(mod.DestinationRejected):
        await mod._send_webhook({"url": f"http://127.0.0.1:{port}/x"}, "e", "m")
    assert http_port.seen == []


@pytest.mark.asyncio
async def test_listed_range_without_a_port_covers_it(monkeypatch, http_port):
    allow(monkeypatch, "127.0.0.0/8")
    port = http_port.server_address[1]
    await mod._send_webhook({"url": f"http://127.0.0.1:{port}/x"}, "e", "m")
    assert len(http_port.seen) == 1


@pytest.mark.asyncio
async def test_name_resolving_outside_the_list_is_refused_at_connect(
    monkeypatch, http_port
):
    """The early check passes, then the name moves to an unlisted address."""
    port = http_port.server_address[1]
    allow(monkeypatch, f"127.0.0.1:{port}")
    real = socket.getaddrinfo
    calls = []

    def rebinding(host, *args, **kwargs):
        if host == "relay.test":
            calls.append(host)
            address = "127.0.0.1" if len(calls) == 1 else "127.0.0.2"
            return [(socket.AF_INET, socket.SOCK_STREAM, 6, "", (address, port))]
        return real(host, *args, **kwargs)

    monkeypatch.setattr(mod.socket, "getaddrinfo", rebinding)
    with pytest.raises(mod.DestinationRejected):
        await mod._send_webhook({"url": f"http://relay.test:{port}/x"}, "e", "m")
    assert http_port.seen == []


@pytest.mark.asyncio
async def test_listed_mail_relay_without_login(monkeypatch, smtp_relay):
    port, seen = smtp_relay
    allow(monkeypatch, f"127.0.0.1:{port}")
    await mod._send_email(email(port), "seal", "alert body")
    assert b"alert body\r\n" in seen


@pytest.mark.asyncio
async def test_listed_mail_relay_accepts_a_login_without_tls(monkeypatch, smtp_relay):
    port, seen = smtp_relay
    allow(monkeypatch, f"127.0.0.1:{port}")
    config = email(port, smtp_user="vault", smtp_password="pw")
    await mod._send_email(config, "seal", "alert body")
    assert any(line.upper().startswith(b"AUTH") for line in seen)


def test_login_without_tls_stays_refused_for_an_unlisted_server(monkeypatch):
    allow(monkeypatch, "")
    with pytest.raises(ValueError, match="require TLS"):
        mod._smtp_send_sync("198.51.100.10", 25, False, False, "user", "password", None)


@pytest.mark.asyncio
async def test_refusal_names_the_setting(monkeypatch):
    allow(monkeypatch, "")
    config = {"url": "http://127.0.0.1:9/x"}
    with pytest.raises(mod.DestinationRejected) as caught:
        await mod._send_webhook(config, "e", "m")
    reason, message = mod._describe_failure("webhook", config, caught.value)
    assert reason == "blocked_destination"
    assert "RH_NOTIFY_INTERNAL_ALLOW" in message


def test_metadata_address_is_refused_even_past_startup_validation(monkeypatch):
    listed = ((ipaddress.IPv4Network("169.254.0.0/16"), None),)
    monkeypatch.setattr(mod, "parse_notify_internal_allow", lambda _value: listed)
    assert mod._internal_allowed("169.254.169.254", 80) is False
    assert mod._internal_allowed("169.254.1.1", 80) is True
