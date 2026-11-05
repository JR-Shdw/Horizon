"""Drive tools/rhorizon-tls against real openssl and stubbed system stores."""

import http.server
import importlib.machinery
import importlib.util
import os
import shutil
import ssl
import stat
import subprocess
import tempfile
import threading
import unittest
import unittest.mock
from pathlib import Path

TOOL = Path(__file__).resolve().parents[1] / "tools/rhorizon-tls"


class Quiet(http.server.BaseHTTPRequestHandler):
    def log_message(self, *_args):
        pass

    def do_GET(self):  # noqa: N802 - stdlib API
        self.send_response(200)
        self.send_header("Content-Length", "2")
        self.end_headers()
        self.wfile.write(b"ok")


def load_tool():
    loader = importlib.machinery.SourceFileLoader("rhorizon_tls", str(TOOL))
    spec = importlib.util.spec_from_loader("rhorizon_tls", loader)
    module = importlib.util.module_from_spec(spec)
    loader.exec_module(module)
    return module


class Server(http.server.ThreadingHTTPServer):
    def handle_error(self, *_args):
        pass


@unittest.skipUnless(shutil.which("openssl"), "openssl is required")
class RhorizonTlsTests(unittest.TestCase):
    def setUp(self):
        temp = tempfile.TemporaryDirectory()
        self.addCleanup(temp.cleanup)
        self.root = Path(temp.name)
        self.certs = self.root / "certs"
        self.log = self.root / "commands.log"
        self.bin = self.root / "bin"
        self.bin.mkdir()
        # Every system command is stubbed: CI runs as root, where the tool
        # skips sudo, and these must never reach the real CA store.
        for name in (
            "sudo",
            "certutil",
            "install",
            "rm",
            "update-ca-certificates",
            "update-ca-trust",
        ):
            self.stub(name)
        self.env = {
            **os.environ,
            "HOME": str(self.root),
            "PATH": f"{self.bin}:{os.environ['PATH']}",
        }

    def stub(self, name):
        path = self.bin / name
        path.write_text(f'#!/bin/sh\necho "{name} $*" >> "{self.log}"\n')
        path.chmod(0o755)

    def tool(self, *args):
        return subprocess.run(
            [str(TOOL), *args],
            capture_output=True,
            text=True,
            env=self.env,
            stdin=subprocess.DEVNULL,
        )

    def generate(self, *extra):
        result = self.tool(
            "generate", "--ip", "192.0.2.10", "--dns", "vault.example",
            "--out", str(self.certs), *extra,
        )  # fmt: skip
        self.assertEqual(result.returncode, 0, result.stderr)
        return result

    def text_of(self, name):
        return subprocess.run(
            ["openssl", "x509", "-in", str(self.certs / name), "-noout", "-text"],
            capture_output=True,
            text=True,
            check=True,
        ).stdout

    def verify(self, *args):
        return subprocess.run(
            ["openssl", "verify", "-x509_strict", "-CAfile"]
            + [str(self.certs / "ca.pem"), *args],
            capture_output=True,
            text=True,
        )

    def sign_with_server_key(self):
        csr = self.root / "forged.csr"
        subprocess.run(
            ["openssl", "req", "-new", "-newkey", "ec", "-pkeyopt"]
            + ["ec_paramgen_curve:prime256v1", "-nodes", "-keyout"]
            + [str(self.root / "forged.key"), "-out", str(csr)]
            + ["-subj", "/CN=bank.example"],
            capture_output=True,
            check=True,
        )
        forged = self.root / "forged.pem"
        extensions = self.root / "forged.ext"
        extensions.write_text("subjectAltName=DNS:bank.example\n")
        subprocess.run(
            ["openssl", "x509", "-req", "-in", str(csr), "-CA"]
            + [str(self.certs / "cert.pem"), "-CAkey", str(self.certs / "key.pem")]
            + ["-set_serial", "1", "-extfile", str(extensions), "-out", str(forged)],
            capture_output=True,
            check=True,
        )
        return forged

    def test_certificate_is_valid_for_every_listed_address(self):
        self.generate()
        server = str(self.certs / "cert.pem")
        for flag, value in (
            ("-verify_ip", "192.0.2.10"),
            ("-verify_ip", "127.0.0.1"),
            ("-verify_hostname", "vault.example"),
            ("-verify_hostname", "localhost"),
        ):
            result = self.verify(flag, value, server)
            self.assertEqual(result.returncode, 0, value + result.stderr)

    def test_certificate_is_rejected_for_an_unlisted_address(self):
        self.generate()
        result = self.verify("-verify_ip", "192.0.2.11", str(self.certs / "cert.pem"))
        self.assertNotEqual(result.returncode, 0)

    def test_server_key_cannot_sign_a_forged_certificate(self):
        self.generate()
        self.assertIn("CA:FALSE", self.text_of("cert.pem"))
        forged = self.sign_with_server_key()
        result = self.verify("-verify_hostname", "bank.example", str(forged))
        self.assertNotEqual(result.returncode, 0)

    def test_ca_is_constrained_and_its_key_is_not_kept(self):
        self.generate()
        self.assertIn("Name Constraints", self.text_of("ca.pem"))
        kept = [path.name for path in self.certs.iterdir()]
        self.assertCountEqual(kept, ["ca.pem", "cert.pem", "key.pem"])

    def test_private_key_is_owner_only_and_ca_file_has_no_key(self):
        self.generate()
        mode = stat.S_IMODE((self.certs / "key.pem").stat().st_mode)
        self.assertEqual(mode, 0o600)
        self.assertNotIn("PRIVATE KEY", (self.certs / "ca.pem").read_text())

    def test_regenerating_keeps_a_backup_and_the_previous_mode(self):
        self.generate()
        (self.certs / "key.pem").chmod(0o640)
        previous = (self.certs / "key.pem").read_bytes()
        self.generate()
        mode = stat.S_IMODE((self.certs / "key.pem").stat().st_mode)
        self.assertEqual(mode, 0o640)
        backups = list(self.certs.glob("key.pem.*.bak"))
        self.assertEqual(len(backups), 1)
        self.assertEqual(backups[0].read_bytes(), previous)

    def test_private_key_is_never_created_with_umask_permissions(self):
        module = load_tool()
        modes = []
        real_open = os.open

        def recording_open(path, flags, mode=0o777, **kwargs):
            modes.append((Path(path).name, flags & os.O_CREAT, mode))
            return real_open(path, flags, mode, **kwargs)

        source = self.root / "source"
        source.write_text("key")
        self.certs.mkdir()
        with unittest.mock.patch.object(module.os, "open", recording_open):
            module.install_file(source, self.certs / "key.pem", 0o600, "stamp")
        self.assertIn((".key.pem.new", os.O_CREAT, 0o600), modes)
        self.assertEqual(stat.S_IMODE((self.certs / "key.pem").stat().st_mode), 0o600)

    def test_system_commands_use_sudo_unless_root(self):
        module = load_tool()
        with (
            unittest.mock.patch.object(module.os, "geteuid", return_value=1000),
            unittest.mock.patch.object(module, "need"),
            unittest.mock.patch.object(module.subprocess, "run") as sudo_run,
        ):
            sudo_run.return_value.returncode = 0
            module.privileged("update-ca-trust", "extract")
        sudo_run.assert_called_once_with(("sudo", "update-ca-trust", "extract"))

        with (
            unittest.mock.patch.object(module.os, "geteuid", return_value=0),
            unittest.mock.patch.object(module, "run") as direct_run,
        ):
            module.privileged("update-ca-trust", "extract")
        direct_run.assert_called_once_with("update-ca-trust", "extract")

    def test_subnet_is_refused_with_a_useful_message(self):
        result = self.tool(
            "generate", "--ip", "198.51.100.0/24", "--out", str(self.certs)
        )
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("exact addresses", result.stderr)
        self.assertFalse((self.certs / "key.pem").exists())

    def test_trust_updates_the_system_and_browser_stores(self):
        self.generate()
        result = self.tool("trust", str(self.certs / "ca.pem"), "--name", "v", "--yes")
        self.assertEqual(result.returncode, 0, result.stderr)
        log = self.log.read_text()
        self.assertIn("rhorizon-v.crt", log)
        self.assertIn("update-ca-", log)
        self.assertIn("-t C,, -n v", log)

    def test_trust_can_target_one_store(self):
        self.generate()
        self.tool(
            "trust", str(self.certs / "ca.pem"), "--name", "v", "--yes", "--browser"
        )
        log = self.log.read_text()
        self.assertNotIn("rhorizon-v.crt", log)
        self.assertNotIn("update-ca-", log)

    def test_wrong_fingerprint_changes_nothing(self):
        self.generate()
        result = self.tool(
            "trust", str(self.certs / "ca.pem"), "--name", "v",
            "--fingerprint", "AA:BB",
        )  # fmt: skip
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("does not match", result.stderr)
        self.assertFalse(self.log.exists())

    def test_unattended_trust_needs_an_explicit_answer(self):
        self.generate()
        result = self.tool("trust", str(self.certs / "ca.pem"), "--name", "v")
        self.assertNotEqual(result.returncode, 0)
        self.assertFalse(self.log.exists())

    def test_private_key_file_cannot_be_trusted(self):
        self.generate()
        result = self.tool("trust", str(self.certs / "key.pem"), "--name", "v", "--yes")
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("private key", result.stderr)

    def test_server_chain_is_refused_in_favour_of_the_ca(self):
        self.generate()
        result = self.tool(
            "trust", str(self.certs / "cert.pem"), "--name", "v", "--yes"
        )
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("use ca.pem", result.stderr)

    def test_unconstrained_ca_is_refused_by_default(self):
        ca = self.root / "wide.pem"
        subprocess.run(
            ["openssl", "req", "-x509", "-newkey", "ec", "-pkeyopt"]
            + ["ec_paramgen_curve:prime256v1", "-nodes", "-keyout"]
            + [str(self.root / "wide.key"), "-out", str(ca), "-subj", "/CN=wide"]
            + ["-addext", "basicConstraints=critical,CA:TRUE"],
            capture_output=True,
            check=True,
        )
        result = self.tool("trust", str(ca), "--name", "v", "--yes")
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("any website", result.stderr)
        self.assertFalse(self.log.exists())

    def test_untrust_removes_from_both_stores(self):
        (self.root / ".pki/nssdb").mkdir(parents=True)
        (self.root / ".pki/nssdb/cert9.db").touch()
        (self.bin / "certutil").write_text(
            f'#!/bin/sh\necho "certutil $*" >> "{self.log}"\nexit 1\n'
        )
        result = self.tool("untrust", "--name", "v")
        self.assertEqual(result.returncode, 0, result.stderr)
        log = self.log.read_text()
        self.assertIn("rm -f", log)
        self.assertIn("-D -n v", log)

    def test_check_passes_with_the_ca_and_fails_without_it(self):
        result = self.tool("generate", "--ip", "127.0.0.1", "--out", str(self.certs))
        self.assertEqual(result.returncode, 0, result.stderr)
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        context.load_cert_chain(self.certs / "cert.pem", self.certs / "key.pem")
        server = Server(("127.0.0.1", 0), Quiet)
        server.socket = context.wrap_socket(server.socket, server_side=True)
        threading.Thread(target=server.serve_forever, daemon=True).start()
        self.addCleanup(server.server_close)
        self.addCleanup(server.shutdown)
        url = f"https://127.0.0.1:{server.server_port}"

        trusted = self.tool("check", url, "--ca-file", str(self.certs / "ca.pem"))
        self.assertEqual(trusted.returncode, 0, trusted.stderr)
        self.assertIn("OK", trusted.stdout)
        untrusted = self.tool("check", url)
        self.assertNotEqual(untrusted.returncode, 0)
        self.assertIn("not trusted", untrusted.stderr)


if __name__ == "__main__":
    unittest.main()
