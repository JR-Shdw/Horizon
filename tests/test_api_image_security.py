"""Execute packaging/scan commands with injected failures: errors must propagate."""

from __future__ import annotations

import os
import re
import subprocess
import tempfile
import unittest
from pathlib import Path

import yaml

ROOT = Path(__file__).resolve().parents[1]


class ApiImageSecurityTests(unittest.TestCase):
    def test_runtime_package_failure_stops_before_cleanup(self) -> None:
        dockerfile = (ROOT / "api/Dockerfile").read_text()
        runtime = dockerfile.split("# Runtime only:", 1)[1].split(
            "# Copy Python packages", 1
        )[0]
        command = runtime[runtime.index("RUN ") + 4 :]
        command = "\n".join(
            line for line in command.splitlines() if not line.lstrip().startswith("#")
        ).replace("\\\n", " ")
        versions = dict(re.findall(r"^ARG (\w+)=(.+)$", dockerfile, re.MULTILINE))

        for operation in ("update", "install"):
            with (
                self.subTest(operation=operation),
                tempfile.TemporaryDirectory() as tmp,
            ):
                directory = Path(tmp)
                marker = directory / "cleanup-ran"
                self._executable(
                    directory,
                    "apt-get",
                    '[ "$1" != "$FAIL_OPERATION" ] || exit 42\nexit 0',
                )
                for name in ("rm", "pip", "find"):
                    self._executable(directory, name, 'printf ran >> "$MARKER"')
                result = subprocess.run(
                    ["/bin/sh", "-c", command],
                    env={
                        **os.environ,
                        **versions,
                        "PATH": tmp,
                        "MARKER": str(marker),
                        "FAIL_OPERATION": operation,
                    },
                    capture_output=True,
                    text=True,
                    check=False,
                )
                self.assertEqual(result.returncode, 42, result.stderr)
                self.assertFalse(marker.exists(), "cleanup masked the package failure")

    def test_api_scan_propagates_scan_and_report_errors(self) -> None:
        workflow = yaml.safe_load((ROOT / ".woodpecker/scan.yml").read_text())
        step = next(step for step in workflow["steps"] if step["name"] == "scan-api")
        command = "\n".join(step["commands"]).replace("$$", "$")

        for operation in ("image", "convert"):
            with (
                self.subTest(operation=operation),
                tempfile.TemporaryDirectory() as tmp,
            ):
                self._executable(
                    Path(tmp),
                    "trivy",
                    '[ "$1" != "$FAIL_OPERATION" ] || exit 43\nexit 0',
                )
                result = subprocess.run(
                    ["/bin/sh", "-c", command],
                    env={**os.environ, "PATH": tmp, "FAIL_OPERATION": operation},
                    capture_output=True,
                    text=True,
                    check=False,
                )
                self.assertEqual(result.returncode, 43, result.stderr)

    @staticmethod
    def _executable(directory: Path, name: str, body: str) -> None:
        path = directory / name
        path.write_text(f"#!/bin/sh\n{body}\n")
        path.chmod(0o755)


if __name__ == "__main__":
    unittest.main()
