"""Exercise the E2E shell helpers under the script's real pipefail settings."""

import json
import subprocess
import unittest
from pathlib import Path

SCRIPT = (Path(__file__).resolve().parents[1] / "tools/k8s-e2e.sh").read_text()


class KubernetesE2EHelperTests(unittest.TestCase):
    def test_secondary_selection_consumes_the_complete_response(self):
        selection = next(
            line.strip()
            for line in SCRIPT.splitlines()
            if line.strip().startswith("secondary_uuid=")
        )
        # A large response makes a prematurely closed pipe reliably visible.
        # Small responses hide the same SIGPIPE race that failed the CI run.
        nodes = [{"ha_state": "primary", "node_uuid": "primary"}] + [
            {"ha_state": "secondary", "node_uuid": f"secondary-{i}"}
            for i in range(20000)
        ]
        result = subprocess.run(
            [
                "bash",
                "-c",
                "set -euo pipefail; ha=$(cat); "
                + selection
                + '; printf "%s" "$secondary_uuid"',
            ],
            input=json.dumps({"nodes": nodes}),
            capture_output=True,
            text=True,
        )
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(result.stdout, "secondary-0")

    def test_unseal_tolerates_a_missing_container_without_numeric_errors(self):
        helper = SCRIPT[
            SCRIPT.index("unseal_pod() {") : SCRIPT.index("\nwait_for_ha_rollout() {")
        ]
        result = subprocess.run(
            [
                "bash",
                "-c",
                "set -euo pipefail; MP=test; pod_exec_request() { return 1; }; "
                + helper
                + "\nunseal_pod missing",
            ],
            capture_output=True,
            text=True,
        )
        self.assertNotEqual(result.returncode, 0)
        self.assertNotIn("integer", result.stderr)


if __name__ == "__main__":
    unittest.main()
