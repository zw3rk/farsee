# SPDX-License-Identifier: Apache-2.0
"""Black-box behaviour tests for the C test runner.

Covers the --filter contract: matching by test name or suite name, and
failing closed when a filter matches nothing. Requires the runner binary;
skips with a documented reason when it has not been built yet.
"""

import os
import subprocess
import unittest

REPO = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", ".."))
RUNNER = os.path.join(REPO, "build", "dev", "bin", "farsee_tests")


def _summary_field(stdout: str, key: str) -> int:
    for line in stdout.splitlines():
        if line.startswith("TESTS"):
            for part in line.split():
                if part.startswith(key + "="):
                    return int(part[len(key) + 1:])
    raise AssertionError("no TESTS summary line in output:\n" + stdout[-2000:])


@unittest.skipUnless(
    os.path.exists(RUNNER), "farsee_tests not built; run `make build` first"
)
class RunnerFilterBehavior(unittest.TestCase):
    def _run(self, *args: str) -> subprocess.CompletedProcess:
        return subprocess.run(
            [RUNNER, *args], capture_output=True, text=True, timeout=300
        )

    def test_filter_by_suite_name_selects_the_suite(self):
        listed = self._run("--list")
        self.assertEqual(listed.returncode, 0, listed.stderr)
        lines = [ln for ln in listed.stdout.splitlines() if ln.strip()]
        self.assertTrue(lines, "--list produced no entries")
        suite = lines[0].split("::", 1)[0]
        result = self._run("--filter", suite)
        self.assertEqual(result.returncode, 0, result.stdout[-2000:])
        self.assertGreater(
            _summary_field(result.stdout, "ran"),
            0,
            "suite-name filter selected nothing",
        )

    def test_filter_by_test_name_still_selects(self):
        listed = self._run("--list")
        name = listed.stdout.splitlines()[0].split("::", 1)[1]
        result = self._run("--filter", name)
        self.assertEqual(result.returncode, 0, result.stdout[-2000:])
        self.assertGreater(_summary_field(result.stdout, "ran"), 0)

    def test_filter_matching_nothing_exits_nonzero(self):
        result = self._run("--filter", "zz_no_such_test_zz123")
        self.assertNotEqual(
            result.returncode,
            0,
            "a filter that matches no tests must fail the run, "
            "not silently pass",
        )
        self.assertIn("no tests matched", result.stderr)


if __name__ == "__main__":
    unittest.main()
