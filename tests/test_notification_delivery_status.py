"""Delivery failures are explained, recorded, and reported to other channels."""

import datetime
import ipaddress
import socket
import ssl
import threading

import httpx
import pytest
from api.app.database import async_session
from api.app.routes import notifications as mod
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import NameOID
from prometheus_client import REGISTRY
from sqlalchemy import text

SECRET_URL = "https://hooks.example.com/services/T000/SECRETPATH?key=SECRETKEY"


def self_signed(tmp_path):
    key = ec.generate_private_key(ec.SECP256R1())
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "127.0.0.1")])
    now = datetime.datetime.now(datetime.UTC)
    cert = (
        x509.CertificateBuilder()
        .subject_name(name)
        .issuer_name(name)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - datetime.timedelta(days=1))
        .not_valid_after(now + datetime.timedelta(days=1))
        .add_extension(
            x509.SubjectAlternativeName(
                [x509.IPAddress(ipaddress.ip_address("127.0.0.1"))]
            ),
            critical=False,
        )
        .sign(key, hashes.SHA256())
    )
    cert_file = tmp_path / "cert.pem"
    key_file = tmp_path / "key.pem"
    cert_file.write_bytes(cert.public_bytes(serialization.Encoding.PEM))
    key_file.write_bytes(
        key.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.PKCS8,
            serialization.NoEncryption(),
        )
    )
    return cert_file, key_file


def serve(handler):
    listener = socket.create_server(("127.0.0.1", 0))

    def loop():
        while True:
            try:
                connection, _ = listener.accept()
            except OSError:
                return
            try:
                handler(connection)
            except OSError:
                pass
            finally:
                connection.close()

    threading.Thread(target=loop, daemon=True).start()
    return listener


@pytest.fixture
def tls_port(tmp_path):
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    context.load_cert_chain(*self_signed(tmp_path))

    def handshake(connection):
        try:
            context.wrap_socket(connection, server_side=True).close()
        except ssl.SSLError:
            pass

    listener = serve(handshake)
    yield listener.getsockname()[1]
    listener.close()


@pytest.fixture
def smtp_without_starttls():
    def answer(connection):
        connection.sendall(b"220 test ESMTP\r\n")
        stream = connection.makefile("rb")
        while line := stream.readline():
            command = line[:4].upper()
            if command == b"QUIT":
                connection.sendall(b"221 bye\r\n")
                return
            connection.sendall(b"250 test\r\n")

    listener = serve(answer)
    yield listener.getsockname()[1]
    listener.close()


@pytest.fixture
def closed_port():
    with socket.socket() as probe:
        probe.bind(("127.0.0.1", 0))
        return probe.getsockname()[1]


@pytest.fixture
def allow_loopback(monkeypatch):
    monkeypatch.setattr(mod, "_is_internal_ip", lambda _address: False)


async def failure_of(channel_type, config):
    with pytest.raises(Exception) as caught:
        await mod._send_notification(channel_type, config, "test", "message")
    return mod._describe_failure(channel_type, config, caught.value)


@pytest.mark.asyncio
async def test_untrusted_webhook_certificate_is_named(allow_loopback, tls_port):
    config = {"url": f"https://127.0.0.1:{tls_port}/SECRETPATH"}
    reason, message = await failure_of("webhook", config)
    assert reason == "tls_certificate"
    assert "self-signed" in message or "self signed" in message
    assert "SECRETPATH" not in message


@pytest.mark.asyncio
async def test_untrusted_matrix_certificate_is_named(allow_loopback, tls_port):
    config = {
        "homeserver": f"https://127.0.0.1:{tls_port}",
        "room_id": "!room",
        "token": "SECRETTOKEN",
    }
    reason, message = await failure_of("matrix", config)
    assert reason == "tls_certificate"
    assert "SECRETTOKEN" not in message and "!room" not in message


@pytest.mark.asyncio
async def test_untrusted_smtp_certificate_is_named(allow_loopback, tls_port):
    config = {
        "smtp_host": "127.0.0.1",
        "smtp_port": tls_port,
        "smtp_use_ssl": True,
        "smtp_user": "alerts",
        "smtp_password": "SECRETPASSWORD",
        "to": ["ops@example.com"],
    }
    reason, message = await failure_of("email", config)
    assert reason == "tls_certificate"
    assert f"127.0.0.1:{tls_port}" in message
    assert "SECRETPASSWORD" not in message


@pytest.mark.asyncio
async def test_smtp_without_starttls_is_named(allow_loopback, smtp_without_starttls):
    config = {
        "smtp_host": "127.0.0.1",
        "smtp_port": smtp_without_starttls,
        "to": ["ops@example.com"],
    }
    reason, message = await failure_of("email", config)
    assert reason == "tls"
    assert "STARTTLS" in message


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "channel_type, config",
    [
        ("webhook", {"url": "http://127.0.0.1:{port}/hook"}),
        (
            "matrix",
            {"homeserver": "http://127.0.0.1:{port}", "room_id": "r", "token": "t"},
        ),
        ("email", {"smtp_host": "127.0.0.1", "smtp_port": "{port}", "to": ["a@b.c"]}),
    ],
)
async def test_refused_connection_is_named(
    allow_loopback, closed_port, channel_type, config
):
    filled = {
        key: value.format(port=closed_port) if isinstance(value, str) else value
        for key, value in config.items()
    }
    reason, message = await failure_of(channel_type, filled)
    assert reason == "connection"
    assert "127.0.0.1" in message


@pytest.mark.asyncio
async def test_private_destination_explains_the_public_address_rule():
    config = {"homeserver": "http://192.168.10.1", "room_id": "r", "token": "t"}
    reason, message = await failure_of("matrix", config)
    assert reason == "blocked_destination"
    assert "public addresses" in message


def test_http_rejection_names_the_credential_and_hides_the_url():
    request = httpx.Request("POST", SECRET_URL)
    response = httpx.Response(401, request=request)
    error = httpx.HTTPStatusError(SECRET_URL, request=request, response=response)
    reason, message = mod._describe_failure("matrix", {"homeserver": SECRET_URL}, error)
    assert reason == "auth"
    assert message == "hooks.example.com rejected the access token (HTTP 401)"


def test_unknown_error_keeps_its_text_out_of_the_message():
    reason, message = mod._describe_failure(
        "webhook", {"url": SECRET_URL}, RuntimeError(SECRET_URL)
    )
    assert reason == "unknown"
    assert "SECRET" not in message


async def add_channel(name, channel_type="webhook", events="[]", enabled=True):
    async with async_session() as db:
        await db.execute(
            text(
                "INSERT INTO vault_notification_channels "
                "(name, channel_type, config, events, enabled) "
                "VALUES (:n, :t, CAST(:c AS jsonb), CAST(:e AS jsonb), :on)"
            ),
            {
                "n": name,
                "t": channel_type,
                "c": f'{{"id": "{name}"}}',
                "e": events,
                "on": enabled,
            },
        )
        await db.commit()


async def state_of(name):
    async with async_session() as db:
        result = await db.execute(
            text(
                "SELECT last_error, consecutive_failures, last_success_at "
                "FROM vault_notification_channels WHERE name = :n"
            ),
            {"n": name},
        )
        return result.fetchone()


@pytest.fixture
async def channels():
    async def wipe():
        async with async_session() as db:
            await db.execute(text("DELETE FROM vault_notification_channels"))
            await db.commit()

    await wipe()
    yield
    await wipe()


@pytest.fixture
def transport(monkeypatch):
    """Channels named in `broken` fail; `sent` records every delivery."""
    state = type("Transport", (), {"broken": set(), "sent": []})()

    async def send(_channel_type, config, event, message):
        if config["id"] in state.broken:
            raise ConnectionRefusedError(111, "refused")
        state.sent.append((config["id"], event, message))

    monkeypatch.setattr(mod, "_send_notification", send)
    return state


async def dispatch(event="honey_access"):
    async with async_session() as db:
        await mod.dispatch_event(db, event, "alert body")


@pytest.mark.asyncio
async def test_first_failure_warns_other_channels_once(channels, transport, caplog):
    await add_channel("mail", "email")
    await add_channel("chat", "matrix", events='["other"]')
    transport.broken = {"mail"}

    await dispatch()
    notices = [s for s in transport.sent if s[1] == "notification_channel_failed"]
    assert [n[0] for n in notices] == ["chat"]
    assert "Channel 'mail' (email) failed" in notices[0][2]
    assert "channel=mail type=email event=honey_access" in caplog.text

    await dispatch()
    notices = [s for s in transport.sent if s[1] == "notification_channel_failed"]
    assert len(notices) == 1
    assert (await state_of("mail")).consecutive_failures == 2


@pytest.mark.asyncio
async def test_disabled_channel_gets_no_warning(channels, transport):
    await add_channel("mail", "email")
    await add_channel("off", enabled=False)
    transport.broken = {"mail"}
    await dispatch()
    assert transport.sent == []


@pytest.mark.asyncio
async def test_recovery_clears_the_failure(channels, transport, caplog):
    await add_channel("mail", "email")
    transport.broken = {"mail"}
    await dispatch()
    assert "refused" in (await state_of("mail")).last_error

    transport.broken = set()
    caplog.set_level("INFO", logger="rhorizon.notify")
    await dispatch()
    state = await state_of("mail")
    assert state.last_error is None
    assert state.consecutive_failures == 0
    assert state.last_success_at is not None
    assert "channel recovered: channel=mail" in caplog.text


@pytest.mark.asyncio
async def test_event_reaching_no_channel_is_counted(channels, transport, caplog):
    await add_channel("mail", "email")
    await add_channel("chat", "matrix")
    transport.broken = {"mail", "chat"}
    labels = {"event": "honey_access"}
    metric = "rhorizon_notification_undelivered_total"
    before = REGISTRY.get_sample_value(metric, labels) or 0

    await dispatch()

    assert REGISTRY.get_sample_value(metric, labels) == before + 1
    assert "Alert not delivered: event=honey_access" in caplog.text


@pytest.mark.asyncio
async def test_status_write_failure_does_not_stop_delivery(channels, transport):
    await add_channel("mail", "email")
    await add_channel("chat", "matrix")

    class ReadOnly:
        def __init__(self, db):
            self.db = db

        async def execute(self, statement, params=None):
            if str(statement).startswith("UPDATE"):
                raise RuntimeError("read-only transaction")
            return await self.db.execute(statement, params)

        def __getattr__(self, name):
            return getattr(self.db, name)

    async with async_session() as db:
        await mod.dispatch_event(ReadOnly(db), "honey_access", "alert body")
    assert sorted(s[0] for s in transport.sent) == ["chat", "mail"]


@pytest.mark.asyncio
async def test_api_reports_the_cause_and_config_change_clears_it(
    channels, client, master_password, admin_token
):
    await client.post("/api/v1/vault/unseal", json={"password": master_password})
    headers = {"Authorization": f"Bearer {admin_token}"}
    created = await client.post(
        "/api/v1/vault/notifications/",
        json={
            "name": "lan-hook",
            "channel_type": "webhook",
            "config": {"url": "http://192.168.10.1/SECRETPATH"},
        },
        headers=headers,
    )
    channel = created.json()["id"]
    base = "/api/v1/vault/notifications/"

    listed = (await client.get(base, headers=headers)).json()["items"][0]
    assert listed["status"] == "untested"

    tested = await client.post(f"{base}{channel}/test", headers=headers)
    assert tested.status_code == 502
    assert "public addresses" in tested.json()["detail"]
    assert "SECRETPATH" not in tested.json()["detail"]

    listed = (await client.get(base, headers=headers)).json()["items"][0]
    assert listed["status"] == "failing"
    assert listed["consecutive_failures"] == 1
    assert listed["last_error"] == tested.json()["detail"]

    await client.put(
        f"{base}{channel}",
        json={"config": {"url": "https://hooks.example.com/new"}},
        headers=headers,
    )
    listed = (await client.get(base, headers=headers)).json()["items"][0]
    assert listed["status"] == "untested"
    assert listed["last_error"] is None
