"""Drive tools/rhorizon-git through real git against a fake vault."""

import datetime
import http.server
import ipaddress
import json
import os
import pty
import ssl
import subprocess
import tempfile
import threading
import unittest
import urllib.parse
from pathlib import Path

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import NameOID

TOOL = Path(__file__).resolve().parents[1] / "tools/rhorizon-git"
GIT_TOKEN = "ghp_fake_stored_token"
VAULT_TOKEN = "rh_fake_vault_token"


class FakeVault(http.server.BaseHTTPRequestHandler):
    secrets: dict[str, str] = {}
    sealed = False

    def log_message(self, *_args):
        pass

    def _send(self, status, payload):
        body = json.dumps(payload).encode()
        self.send_response(status)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self):  # noqa: N802 - stdlib API
        parts = urllib.parse.urlsplit(self.path)
        if parts.path == "/api/v1/vault/status":
            self._send(200, {"sealed": self.sealed})
        elif self.headers.get("Authorization") != f"Bearer {VAULT_TOKEN}":
            self._send(401, {})
        elif parts.path == "/api/v1/vault/tokens/whoami":
            self._send(200, {"name": "test"})
        elif parts.path == "/api/v1/vault/secrets/":
            items = [
                {"namespace": ref.split("/")[0], "name": ref.split("/")[1]}
                for ref in self.secrets
            ]
            self._send(200, {"items": items})
        else:
            name = parts.path.rsplit("/", 1)[1]
            namespace = urllib.parse.parse_qs(parts.query)["namespace"][0]
            ref = f"{namespace}/{name}"
            if ref in self.secrets:
                self._send(200, {"value": self.secrets[ref]})
            else:
                self._send(404, {})


def write_self_signed(cert_path, key_path, host):
    key = ec.generate_private_key(ec.SECP256R1())
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "vault-test")])
    now = datetime.datetime.now(datetime.timezone.utc)
    public = key.public_key()
    cert = (
        x509.CertificateBuilder()
        .subject_name(name)
        .issuer_name(name)
        .public_key(public)
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - datetime.timedelta(minutes=5))
        .not_valid_after(now + datetime.timedelta(days=1))
        .add_extension(
            x509.SubjectAlternativeName([x509.IPAddress(ipaddress.ip_address(host))]),
            critical=False,
        )
        .add_extension(x509.BasicConstraints(ca=True, path_length=0), critical=True)
        .add_extension(
            x509.NameConstraints(
                permitted_subtrees=[
                    x509.IPAddress(ipaddress.ip_network(f"{host}/32")),
                ],
                excluded_subtrees=None,
            ),
            critical=True,
        )
        .add_extension(
            x509.SubjectKeyIdentifier.from_public_key(public), critical=False
        )
        .add_extension(
            x509.AuthorityKeyIdentifier.from_issuer_public_key(public), critical=False
        )
        .sign(key, hashes.SHA256())
    )
    cert_path.write_bytes(cert.public_bytes(serialization.Encoding.PEM))
    key_path.write_bytes(
        key.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.PKCS8,
            serialization.NoEncryption(),
        )
    )


class RhorizonGitTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.server = http.server.ThreadingHTTPServer(("127.0.0.1", 0), FakeVault)
        threading.Thread(target=cls.server.serve_forever, daemon=True).start()
        cls.vault_url = f"http://127.0.0.1:{cls.server.server_port}"

    @classmethod
    def tearDownClass(cls):
        cls.server.shutdown()

    def setUp(self):
        FakeVault.secrets = {"git/app-github": GIT_TOKEN}
        FakeVault.sealed = False
        temp = tempfile.TemporaryDirectory()
        self.addCleanup(temp.cleanup)
        self.root = Path(temp.name)
        self.repo = self.root / "repo"
        self.token_file = self.root / "vault.token"
        self.token_file.write_text(VAULT_TOKEN + "\n")
        self.token_file.chmod(0o600)
        self.env = {
            **os.environ,
            "HOME": str(self.root),
            "RH_CONFIG_DIR": str(self.root / "config"),
            "GIT_CONFIG_NOSYSTEM": "1",
        }
        subprocess.run(["git", "init", "-q", str(self.repo)], check=True, env=self.env)
        self.git("remote", "add", "origin", "https://gitea.example/me/app.git")

    def git(self, *args, **kwargs):
        return subprocess.run(
            ["git", "-C", str(self.repo), *args],
            capture_output=True,
            text=True,
            env=self.env,
            **kwargs,
        )

    def setup_tool(self, *extra, url="https://github.com/acme/app.git"):
        return subprocess.run(
            [
                str(TOOL),
                "setup",
                "--repo",
                str(self.repo),
                "--remote",
                "origin",
                "--url",
                url,
                "--vault-url",
                self.vault_url,
                "--token-file",
                str(self.token_file),
                "--secret",
                "git/app-github",
                "--yes",
                *extra,
            ],
            capture_output=True,
            text=True,
            env=self.env,
            stdin=subprocess.DEVNULL,
        )

    def fill(self, url="https://github.com/acme/app.git"):
        return self.git("credential", "fill", input=f"url={url}\n\n", timeout=30)

    def test_git_receives_the_vault_token_for_the_linked_host(self):
        result = self.setup_tool("--no-verify")
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(
            self.git("remote", "get-url", "origin").stdout.strip(),
            "https://github.com/acme/app.git",
        )
        filled = self.fill()
        self.assertEqual(filled.returncode, 0, filled.stderr)
        self.assertIn(f"password={GIT_TOKEN}", filled.stdout)
        self.assertIn("username=x-access-token", filled.stdout)

    def test_token_is_never_written_to_git_config(self):
        self.setup_tool("--no-verify")
        config = (self.repo / ".git/config").read_text()
        self.assertNotIn(GIT_TOKEN, config)
        self.assertNotIn(VAULT_TOKEN, config)
        self.assertIn("git/app-github", config)

    def test_inherited_helper_is_dropped_for_the_linked_host_only(self):
        self.git(
            "config",
            "--global",
            "credential.helper",
            "!printf 'username=u\\npassword=wrong\\n' #",
        )
        self.setup_tool("--no-verify")
        self.assertIn(f"password={GIT_TOKEN}", self.fill().stdout)
        other = self.fill("https://other.example/x.git")
        self.assertIn("password=wrong", other.stdout)

    def test_embedded_credential_and_ssh_urls_are_cleaned(self):
        for url in (
            "https://user:old_token@github.com/acme/app.git",
            "git@github.com:acme/app.git",
        ):
            result = self.setup_tool("--no-verify", url=url)
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertEqual(
                self.git("remote", "get-url", "origin").stdout.strip(),
                "https://github.com/acme/app.git",
            )

    def test_failed_remote_check_restores_previous_settings(self):
        target = f"http://127.0.0.1:{self.server.server_port}/missing.git"
        result = self.setup_tool("--username", "me", url=target)
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("previous settings restored", result.stderr)
        self.assertEqual(
            self.git("remote", "get-url", "origin").stdout.strip(),
            "https://gitea.example/me/app.git",
        )
        self.assertNotIn("rhorizon-git", (self.repo / ".git/config").read_text())

    def test_nothing_changes_when_the_secret_is_missing_or_vault_sealed(self):
        before = (self.repo / ".git/config").read_text()
        FakeVault.secrets = {}
        self.assertNotEqual(self.setup_tool().returncode, 0)
        FakeVault.secrets = {"git/app-github": GIT_TOKEN}
        FakeVault.sealed = True
        result = self.setup_tool()
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("sealed", result.stderr)
        self.assertEqual((self.repo / ".git/config").read_text(), before)

    def test_plain_http_remote_is_refused(self):
        result = self.setup_tool("--no-verify", url="http://github.com/acme/app.git")
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("plain http", result.stderr)

    def test_open_vault_token_file_is_refused(self):
        self.token_file.chmod(0o644)
        result = self.setup_tool("--no-verify")
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("too open", result.stderr)

    def test_multiline_secret_cannot_inject_credential_attributes(self):
        self.setup_tool("--no-verify")
        FakeVault.secrets = {"git/app-github": "tok\nhost=evil.example"}
        filled = self.fill()
        self.assertNotIn("evil.example", filled.stdout)

    def test_interactive_flow_saves_a_vault_profile_for_the_next_repo(self):
        answers = [
            str(self.repo),
            "1",
            "https://github.com/acme/app.git",
            "1",
            "lab",
            self.vault_url,
            str(self.token_file),
            "1",
            "y",
        ]
        controller, terminal = pty.openpty()
        self.addCleanup(os.close, controller)
        os.write(controller, ("\n".join(answers) + "\n").encode())
        result = subprocess.run(
            [str(TOOL), "setup", "--no-verify"],
            stdin=terminal,
            capture_output=True,
            text=True,
            env=self.env,
            timeout=30,
        )
        os.close(terminal)
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertIn(f"password={GIT_TOKEN}", self.fill().stdout)
        profile = self.root / "config/vaults.ini"
        self.assertEqual(profile.stat().st_mode & 0o777, 0o600)
        self.assertIn("[lab]", profile.read_text())
        self.assertNotIn(VAULT_TOKEN, profile.read_text())

    def interactive(self, answers):
        controller, terminal = pty.openpty()
        self.addCleanup(os.close, controller)
        os.write(controller, ("\n".join(answers) + "\n").encode())
        result = subprocess.run(
            [str(TOOL), "setup", "--no-verify"],
            stdin=terminal,
            capture_output=True,
            text=True,
            env=self.env,
            timeout=30,
        )
        os.close(terminal)
        return result

    def test_url_typed_as_remote_name_is_asked_again(self):
        url = "https://github.com/acme/app.git"
        result = self.interactive(
            [str(self.repo), "2", url, "github", url, "1", "lab"]
            + [self.vault_url, str(self.token_file), "1", "y"]
        )
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertIn("not a URL", result.stdout)
        self.assertEqual(self.git("remote", "get-url", "github").stdout.strip(), url)
        self.assertEqual(
            self.git("remote", "get-url", "origin").stdout.strip(),
            "https://gitea.example/me/app.git",
        )

    def test_rejected_vault_token_does_not_save_a_profile(self):
        self.token_file.write_text("rh_wrong\n")
        result = self.interactive(
            [str(self.repo), "1", "https://github.com/acme/app.git", "1", "lab"]
            + [self.vault_url, str(self.token_file)]
        )
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("rejected", result.stderr)
        self.assertFalse((self.root / "config/vaults.ini").exists())

    def test_open_token_file_can_be_tightened_during_setup(self):
        self.token_file.chmod(0o644)
        result = self.interactive(
            [str(self.repo), "1", "https://github.com/acme/app.git", "1", "lab"]
            + [self.vault_url, str(self.token_file), "y", "1", "y"]
        )
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertEqual(self.token_file.stat().st_mode & 0o777, 0o600)

    def tls_vault(self, host="127.0.0.1"):
        cert, key = self.root / "cert.pem", self.root / "key.pem"
        write_self_signed(cert, key, host)
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        context.load_cert_chain(cert, key)
        server = http.server.ThreadingHTTPServer(("127.0.0.1", 0), FakeVault)
        server.socket = context.wrap_socket(server.socket, server_side=True)
        threading.Thread(target=server.serve_forever, daemon=True).start()
        self.addCleanup(server.server_close)
        self.addCleanup(server.shutdown)
        return f"https://127.0.0.1:{server.server_port}", cert

    def setup_vault(self, vault_url, *extra):
        return subprocess.run(
            [str(TOOL), "setup", "--repo", str(self.repo), "--remote", "origin"]
            + ["--url", "https://github.com/acme/app.git", "--vault-url", vault_url]
            + ["--token-file", str(self.token_file), "--secret", "git/app-github"]
            + ["--yes", "--no-verify", *extra],
            capture_output=True,
            text=True,
            env=self.env,
            stdin=subprocess.DEVNULL,
        )

    def test_tls_vault_with_ca_file_serves_git_end_to_end(self):
        url, cert = self.tls_vault()
        result = self.setup_vault(url, "--ca-file", str(cert))
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn(f"password={GIT_TOKEN}", self.fill().stdout)

    def test_untrusted_tls_vault_is_refused(self):
        url, _cert = self.tls_vault()
        result = self.setup_vault(url)
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("certificate not trusted", result.stderr)

    def test_certificate_for_another_host_is_refused_even_with_its_ca(self):
        url, cert = self.tls_vault(host="192.0.2.10")
        result = self.setup_vault(url, "--ca-file", str(cert))
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("certificate not trusted", result.stderr)

    def test_plain_http_vault_outside_loopback_is_refused(self):
        result = self.setup_vault("http://127.0.0.2:1")
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("plain http", result.stderr)
        self.assertNotIn("rhorizon-git", (self.repo / ".git/config").read_text())

    def test_insecure_flag_is_explicit_and_kept_in_the_helper(self):
        result = self.setup_vault("http://127.0.0.2:1", "--allow-insecure-vault")
        self.assertIn("unreachable", result.stderr)
        self.assertNotIn("plain http, tokens would", result.stderr)

    def test_credential_mode_also_refuses_a_plain_http_vault(self):
        result = subprocess.run(
            [str(TOOL), "credential", "--vault-url", "http://127.0.0.2:1"]
            + ["--token-file", str(self.token_file), "--secret", "git/app-github"]
            + ["--username", "u", "get"],
            input="protocol=https\nhost=github.com\n\n",
            capture_output=True,
            text=True,
            env=self.env,
        )
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("plain http", result.stderr)
        self.assertNotIn("password=", result.stdout)

    def test_status_shows_the_linked_secret_without_a_value(self):
        self.setup_tool("--no-verify")
        result = subprocess.run(
            [str(TOOL), "status", "--repo", str(self.repo)],
            capture_output=True,
            text=True,
            env=self.env,
        )
        self.assertIn("secret: git/app-github", result.stdout)
        self.assertNotIn(GIT_TOKEN, result.stdout)


if __name__ == "__main__":
    unittest.main()
