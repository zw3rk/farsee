# SPDX-License-Identifier: Apache-2.0
"""Regression tests for the release license and dependency policy gates."""

from __future__ import annotations

import importlib.util
import json
import re
import subprocess
import tempfile
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]
SPEC = importlib.util.spec_from_file_location(
    "check_license", ROOT / "tools" / "check_license.py"
)
assert SPEC is not None and SPEC.loader is not None
CHECK_LICENSE = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(CHECK_LICENSE)


def write(path: Path, text: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text, encoding="utf-8")


class ReleasePolicyTests(unittest.TestCase):
    def test_release_link_drops_devshell_output_runpath(self) -> None:
        workspace = "/" + "home/runner/work/farsee/farsee"
        output = subprocess.run(
            [
                "make", "-s", "--no-print-directory", "BUILD=release",
                f"out={workspace}/outputs/out",
                (
                    "NIX_LDFLAGS=-rpath "
                    f"{workspace}/outputs/out/lib -L/nix/store/example/lib"
                ),
                "--eval",
                "print-release-ldflags:;@printf '%s\\n' "
                "\"$(RELEASE_NIX_LDFLAGS)\"",
                "print-release-ldflags",
            ],
            cwd=ROOT,
            check=False,
            capture_output=True,
            text=True,
        )
        self.assertEqual(output.returncode, 0, output.stderr)
        self.assertEqual(output.stdout.strip(), "-L/nix/store/example/lib")

    def test_default_tests_include_cli_dispatch_smoke(self) -> None:
        makefile = (ROOT / "Makefile").read_text(encoding="utf-8")
        test_target = re.search(r"^test:([^\n]*)", makefile, re.MULTILINE)
        cli_smoke = re.search(
            r"^cli-smoke:([^\n]*)\n(?P<body>(?:\t.*\n)+)",
            makefile,
            re.MULTILINE,
        )
        self.assertIsNotNone(test_target)
        self.assertIsNotNone(cli_smoke)
        assert test_target is not None and cli_smoke is not None
        self.assertIn("cli-smoke", test_target.group(1).split("##", 1)[0])
        body = cli_smoke.group("body")
        for form in (
            "--help",
            "--version",
            "--protocol-capabilities",
            "--protocol rdp",
            "--protocol vnc --auth vnc",
            "--protocol vnc --auth apple",
        ):
            self.assertIn(form, body)
        self.assertIn("status", body)

    def test_coverage_threshold_rows_name_nonempty_source_modules(self) -> None:
        thresholds = ROOT / "tools" / "coverage-thresholds.tsv"
        for number, raw in enumerate(
            thresholds.read_text(encoding="utf-8").splitlines(), start=1
        ):
            line = raw.strip()
            if not line or line.startswith("#"):
                continue
            module = line.split("\t", 1)[0]
            if module == "*":
                continue
            sources = list((ROOT / "src" / module).rglob("*.c"))
            self.assertTrue(
                sources,
                f"coverage threshold row {number} names empty module {module}",
            )

    def test_release_check_rejects_every_wlog_cli_form(self) -> None:
        makefile = (ROOT / "Makefile").read_text(encoding="utf-8")
        release_check = makefile.split("release-check:", 1)[1].split("\n\n", 1)[0]
        self.assertIn("check-release-wlog-policy", release_check)
        recipe = makefile.split("check-release-wlog-policy:", 1)[1].split(
            "\n\n", 1
        )[0]
        for form in (
            "-v",
            "--verbose",
            "--log-level",
            "--log-level=info",
            "--help --verbose",
            "--version --log-level=trace",
            "--protocol-capabilities -v",
        ):
            self.assertIn(form, recipe)
        self.assertIn("status", recipe)
        self.assertIn("developer build", recipe)

    def test_release_version_gate_accepts_match_and_rejects_mismatch(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            binary = Path(raw) / "farsee"
            write(binary, "#!/bin/sh\necho 'farsee 1.2.3 git=test built=test'\n")
            binary.chmod(0o755)
            common = [
                "make", "-s", "check-release-version",
                f"RELEASE_BINARY={binary}",
            ]
            accepted = subprocess.run(
                [*common, "VERSION=1.2.3"], cwd=ROOT, check=False,
                capture_output=True, text=True,
            )
            rejected = subprocess.run(
                [*common, "VERSION=1.2.4"], cwd=ROOT, check=False,
                capture_output=True, text=True,
            )
            self.assertEqual(accepted.returncode, 0, accepted.stderr)
            self.assertNotEqual(rejected.returncode, 0)
            self.assertIn("version mismatch", rejected.stderr)

    def test_release_artifacts_audit_the_binary_that_is_packaged(self) -> None:
        makefile = (ROOT / "Makefile").read_text(encoding="utf-8")
        stage = re.search(
            r"^release-stage:([^\n]*)\n(?P<body>(?:\t.*\n)+)",
            makefile,
            re.MULTILINE,
        )
        artifacts = re.search(
            r"^release-artifacts:([^\n]*)\n(?P<body>(?:\t.*\n)+)",
            makefile,
            re.MULTILINE,
        )
        self.assertIsNotNone(stage)
        self.assertIsNotNone(artifacts)
        assert stage is not None and artifacts is not None
        self.assertIn("release", stage.group(1).split("##", 1)[0].split())
        self.assertNotIn("release-cli", stage.group(1))
        body = artifacts.group("body")
        self.assertIn("RELEASE_BINARY=$(BUILD_DIR)/release/bin/farsee", body)
        for gate in (
            "check-runtime-closure",
            "check-release-binary",
            "check-release-version",
            "check-release-wlog-policy",
            "trace-release-check",
            "apple-preservation-check",
        ):
            self.assertIn(gate, body)
        self.assertIn("--without-rdp", makefile)
        self.assertIn("runtime-closure.txt", body)
        self.assertIn("gen_release_metadata.py", stage.group("body"))
        self.assertIn("release_path_guard.py --prepare stage", stage.group("body"))
        self.assertIn("install -d -m755", stage.group("body"))
        self.assertNotIn("mkdir -p", stage.group("body"))
        self.assertNotIn("rm -rf", stage.group("body"))
        self.assertIn("release_path_guard.py --prepare artifacts", body)
        self.assertIn("--source-name farsee", body)
        self.assertIn("--source-version $(VERSION)", body)
        self.assertIn("release_sbom.py", body)
        self.assertIn(
            "--manifest '$(RELEASE_STAGE)/share/doc/farsee/dependencies.json'",
            body,
        )
        self.assertIn("--runtime-closure", body)
        self.assertIn("--binary '$(RELEASE_STAGE)/bin/farsee'", body)
        self.assertIn("trace-release-artifacts-check", body)
        self.assertNotIn("rm -rf", body)

    def test_release_workflow_runs_current_and_history_trace_gates(self) -> None:
        workflow = (ROOT / ".github" / "workflows" / "release.yml").read_text()
        self.assertIn("trace-current-check", workflow)
        self.assertIn("history-trace-check", workflow)
        self.assertIn("check-secrets", workflow)
        self.assertIn("check-reproducible", workflow)

    def test_release_trace_scans_generated_source_not_compiler_outputs(self) -> None:
        makefile = (ROOT / "Makefile").read_text(encoding="utf-8")
        recipe = makefile.split("trace-release-check:", 1)[1].split("\n\n", 1)[0]
        self.assertNotIn("--generated-root $(GEN_DIR)", recipe)
        for generated_source in ("$(BUILD_ID_H)", "$(GEN_INCLUDE)",
                                 "$(GEN_REGISTRY)"):
            self.assertIn(f"--generated-root {generated_source}", recipe)

    def test_release_artifact_trace_scans_final_metadata(self) -> None:
        makefile = (ROOT / "Makefile").read_text(encoding="utf-8")
        recipe = makefile.split(
            "trace-release-artifacts-check:", 1
        )[1].split("\n\n", 1)[0]
        for value in (
            "$(RELEASE_STAGE)/share/doc/farsee",
            "$(RELEASE_SBOM)",
            "$(RELEASE_NOTES)",
            "$(RELEASE_CHECKSUMS)",
        ):
            self.assertIn(value, recipe)

    def test_reproducibility_gate_compares_complete_artifact_sets(self) -> None:
        script = (ROOT / "tools" / "check_reproducible.sh").read_text(
            encoding="utf-8"
        )
        self.assertIn("release-artifacts", script)
        self.assertIn("timeout", script)
        for value in (
            "farsee-$VERSION-$PLATFORM.tar.gz",
            "farsee-$VERSION-$PLATFORM.spdx.json",
            "farsee-$VERSION-release-notes.md",
            "SHA256SUMS",
        ):
            self.assertIn(value, script)

    def test_no_rdp_release_configuration_has_full_release_gates(self) -> None:
        makefile = (ROOT / "Makefile").read_text(encoding="utf-8")
        release_target = makefile.split(
            "no-rdp-release-check:", 1
        )[1].split("\n\n", 1)[0]
        reproducible_target = makefile.split(
            "check-reproducible-no-rdp:", 1
        )[1].split("\n\n", 1)[0]
        ci_target = makefile.split("\nci:", 1)[1].split("\n\n", 1)[0]
        workflow = (ROOT / ".github/workflows/release.yml").read_text(
            encoding="utf-8"
        )

        self.assertIn("FARSEE_WITH_RDP=0", release_target)
        self.assertIn("release-check", release_target)
        self.assertIn("FARSEE_WITH_RDP=0", reproducible_target)
        self.assertIn("check-reproducible", reproducible_target)
        self.assertIn("no-rdp-check", ci_target)
        self.assertIn("no-rdp-release-check", ci_target)
        self.assertIn("no-rdp-release-check", workflow)
        self.assertIn("check-reproducible-no-rdp", workflow)

    def test_release_artifacts_are_limited_to_approved_platforms(self) -> None:
        makefile = (ROOT / "Makefile").read_text(encoding="utf-8")
        stage_header = re.search(
            r"^release-stage:([^\n]*)", makefile, re.MULTILINE
        )
        workflow = (ROOT / ".github/workflows/release.yml").read_text(
            encoding="utf-8"
        )
        manifest = json.loads(
            (ROOT / "release/dependencies.json").read_text(encoding="utf-8")
        )

        self.assertIsNotNone(stage_header)
        assert stage_header is not None
        self.assertIn("check-release-platform", stage_header.group(1))
        self.assertEqual(
            manifest["release_platforms"],
            ["aarch64-darwin", "x86_64-darwin"],
        )
        artifact_job = re.search(
            r"(?ms)^  release-candidate:\n(?P<body>.*?)(?=^  [a-z][a-z-]+:|\Z)",
            workflow,
        )
        self.assertIsNotNone(artifact_job)
        assert artifact_job is not None
        self.assertIn("runs-on: macos-latest", artifact_job.group("body"))
        self.assertNotIn("ubuntu", artifact_job.group("body"))

    def test_release_automation_requires_governance_approval(self) -> None:
        makefile = (ROOT / "Makefile").read_text(encoding="utf-8")
        workflow = (ROOT / ".github/workflows/release.yml").read_text(
            encoding="utf-8"
        )
        sign_header = re.search(
            r"^release-sign:([^\n]*)", makefile, re.MULTILINE
        )

        self.assertIsNotNone(sign_header)
        assert sign_header is not None
        self.assertIn("check-release-approval", sign_header.group(1))
        self.assertIn("check-release-approval", workflow)
        self.assertNotRegex(workflow, r"(?m)^\s*push:\s*$")
        self.assertLess(
            workflow.index("check-release-approval"),
            workflow.index("release-artifacts"),
        )

    def test_release_workflow_verifies_the_exact_candidate_on_both_hosts(self) -> None:
        workflow = (ROOT / ".github" / "workflows" / "release.yml").read_text(
            encoding="utf-8"
        )
        verify_job = re.search(
            r"(?ms)^  verify-candidate:\n(?P<body>.*?)(?=^  [a-z][a-z-]+:|\Z)",
            workflow,
        )
        self.assertIsNotNone(verify_job)
        assert verify_job is not None
        body = verify_job.group("body")
        self.assertIn("os: [macos-latest, ubuntu-latest]", body)
        self.assertIn("nix build .#default -L", body)
        self.assertRegex(body, r"\bmake\b[\s\\\n-]*.*\bci\b")
        self.assertIn('VERSION="$VERSION" ci', body)
        self.assertIn("fuzz-release", body)

        artifact_job = re.search(
            r"(?ms)^  release-candidate:\n(?P<body>.*?)(?=^  [a-z][a-z-]+:|\Z)",
            workflow,
        )
        self.assertIsNotNone(artifact_job)
        assert artifact_job is not None
        self.assertIn("needs: verify-candidate", artifact_job.group("body"))

    def test_release_workflow_can_publish_an_explicit_tag_and_release(self) -> None:
        workflow = (ROOT / ".github" / "workflows" / "release.yml").read_text(
            encoding="utf-8"
        )
        self.assertIn("publish:", workflow)
        self.assertIn("type: boolean", workflow)
        self.assertIn("contents: write", workflow)
        self.assertIn("actions/download-artifact@", workflow)
        self.assertIn("gh release create", workflow)
        self.assertIn("--verify-tag", workflow)
        self.assertIn("git tag -a", workflow)
        self.assertIn("git push origin", workflow)
        self.assertLess(
            workflow.index("check-release-approval"),
            workflow.index("git tag -a"),
        )

    def test_macos_acceptance_is_exposed_through_make(self) -> None:
        makefile = (ROOT / "Makefile").read_text(encoding="utf-8")
        target = re.search(
            r"^macos-acceptance:([^\n]*)\n(?P<body>(?:\t.*\n)+)",
            makefile,
            re.MULTILINE,
        )
        self.assertIsNotNone(target)
        assert target is not None
        self.assertIn("release-cli", target.group(1))
        self.assertIn("macos_acceptance.sh", target.group("body"))
        self.assertIn("MACOS_ACCEPTANCE_HOST", target.group("body"))

    def test_rdp_interop_is_exposed_through_make(self) -> None:
        makefile = (ROOT / "Makefile").read_text(encoding="utf-8")
        target = re.search(
            r"^rdp-interop:([^\n]*)\n(?P<body>(?:\t.*\n)+)",
            makefile,
            re.MULTILINE,
        )
        self.assertIsNotNone(target)
        assert target is not None
        self.assertIn("release-cli", target.group(1))
        self.assertIn("rdp_interop_matrix.sh", target.group("body"))
        self.assertIn("RDP_INTEROP_EVIDENCE_DIR", target.group("body"))
        self.assertIn("RDP_INTEROP_PHASE", target.group("body"))

    def test_absent_promo_tree_has_no_workflow_residue(self) -> None:
        self.assertFalse((ROOT / "docs" / "demos" / "promo").exists())
        makefile = (ROOT / "Makefile").read_text(encoding="utf-8")
        self.assertNotIn("PROMO_", makefile)
        self.assertNotRegex(makefile, r"(?m)^promo-[a-z-]+:")
        self.assertNotIn("NPM", makefile)
        flake = (ROOT / "flake.nix").read_text()
        for package in ("pkgs.nodejs_22", "pkgs.curl", "pkgs.ffmpeg"):
            self.assertNotIn(package, flake)
        self.assertNotIn("docs/demos", flake)
        ignores = (ROOT / ".gitignore").read_text(encoding="utf-8")
        self.assertNotIn("docs/demos", ignores)
        notices = (ROOT / "THIRD_PARTY_NOTICES.md").read_text(
            encoding="utf-8"
        )
        self.assertNotIn("Promo build dependencies", notices)
        self.assertNotIn("Demo media only", notices)
        self.assertFalse(hasattr(CHECK_LICENSE, "audit_promo_lock_data"))
        self.assertFalse(hasattr(CHECK_LICENSE, "audit_promo_dependencies"))

    def test_minimized_freerdp_drops_unused_darwin_link_inputs(self) -> None:
        flake = (ROOT / "flake.nix").read_text(encoding="utf-8")
        self.assertIn(
            "-DCMAKE_SHARED_LINKER_FLAGS=-Wl,-dead_strip_dylibs",
            flake,
        )

    def test_non_c_script_without_spdx_is_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            write(root / "tools" / "bad.py", "#!/usr/bin/env python3\n")
            count, errors = CHECK_LICENSE.audit_first_party(root)
            self.assertEqual(count, 1)
            self.assertTrue(any("bad.py" in error and "SPDX" in error
                                for error in errors))

    def test_windows_vm_sources_without_spdx_are_rejected(self) -> None:
        for name in ("bad.cmd", "bad.xml", "bad.ini"):
            with self.subTest(name=name), tempfile.TemporaryDirectory() as td:
                root = Path(td)
                write(root / "tools" / "windows-vm" / name, "content\n")
                count, errors = CHECK_LICENSE.audit_first_party(root)
                self.assertEqual(count, 1)
                self.assertTrue(any(name in error and "SPDX" in error
                                    for error in errors))

    def test_windows_vm_sources_with_spdx_are_accepted(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            write(root / "tools" / "windows-vm" / "good.cmd",
                  "REM SPDX-License-Identifier: Apache-2.0\n")
            write(root / "tools" / "windows-vm" / "good.xml",
                  "<!-- SPDX-License-Identifier: Apache-2.0 -->\n")
            write(root / "tools" / "windows-vm" / "good.ini",
                  "; SPDX-License-Identifier: Apache-2.0\n")
            count, errors = CHECK_LICENSE.audit_first_party(root)
            self.assertEqual(count, 3)
            self.assertEqual(errors, [])

    def test_non_c_script_with_spdx_is_accepted(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            write(
                root / "tools" / "good.sh",
                "#!/bin/sh\n# SPDX-License-Identifier: Apache-2.0\n",
            )
            count, errors = CHECK_LICENSE.audit_first_party(root)
            self.assertEqual(count, 1)
            self.assertEqual(errors, [])

    def test_manifest_rejects_forbidden_transitive_license(self) -> None:
        manifest = {
            "schema": 1,
            "allowed_licenses": ["Apache-2.0"],
            "dependencies": [
                {
                    "name": "badcodec",
                    "version": "1.0",
                    "license": "GPL-3.0-only",
                    "store_patterns": ["badcodec-"],
                    "notice": "### badcodec",
                }
            ],
        }
        errors = CHECK_LICENSE.audit_dependency_manifest_data(manifest, "notices")
        self.assertTrue(any("GPL-3.0-only" in error for error in errors))

    def test_manifest_requires_notice_and_version(self) -> None:
        manifest = {
            "schema": 1,
            "allowed_licenses": ["Apache-2.0"],
            "dependencies": [
                {
                    "name": "freerdp",
                    "version": "3.15.0",
                    "license": "Apache-2.0",
                    "store_patterns": ["freerdp-3.15.0"],
                    "notice": "### FreeRDP 3.15.0",
                }
            ],
        }
        errors = CHECK_LICENSE.audit_dependency_manifest_data(
            manifest, "### FreeRDP\n"
        )
        self.assertTrue(any("notice marker" in error for error in errors))

    def test_runtime_closure_rejects_undeclared_store_path(self) -> None:
        manifest = {
            "schema": 1,
            "allowed_licenses": ["Apache-2.0"],
            "dependencies": [
                {
                    "name": "freerdp",
                    "version": "3.15.0",
                    "license": "Apache-2.0",
                    "store_patterns": ["freerdp-3.15.0"],
                    "notice": "### FreeRDP 3.15.0",
                }
            ],
            "forbidden_runtime_patterns": ["ffmpeg", "libavcodec"],
        }
        errors = CHECK_LICENSE.audit_runtime_paths_data(
            manifest,
            [
                "/nix/store/aaaa-freerdp-3.15.0/lib/libfreerdp3.so",
                "/nix/store/bbbb-ffmpeg-7.1.1/lib/libavcodec.so",
            ],
        )
        self.assertTrue(any("forbidden runtime dependency" in error
                            for error in errors))

    def test_runtime_closure_accepts_only_exact_declared_system_lib(self) -> None:
        manifest = {
            "schema": 1,
            "allowed_licenses": ["Apache-2.0"],
            "dependencies": [
                {
                    "name": "freerdp",
                    "version": "3.15.0",
                    "license": "Apache-2.0",
                    "store_patterns": ["freerdp-3.15.0"],
                    "notice": "### FreeRDP 3.15.0",
                }
            ],
            "forbidden_runtime_patterns": ["ffmpeg"],
            "system_libraries": [
                {
                    "name": "Apple system runtime",
                    "license": "Apple system library",
                    "paths": ["/usr/lib/libSystem.B.dylib"],
                    "notice": "### Apple platform runtime",
                }
            ],
        }
        errors = CHECK_LICENSE.audit_runtime_paths_data(
            manifest,
            [
                "/nix/store/aaaa-freerdp-3.15.0/lib/libfreerdp3.so",
                "/usr/lib/libSystem.B.dylib",
            ],
        )
        self.assertEqual(errors, [])

        errors = CHECK_LICENSE.audit_runtime_paths_data(
            manifest, ["/usr/lib/libUndeclared.dylib"]
        )
        self.assertTrue(any("undeclared system runtime" in error
                            for error in errors))

    def test_manifest_rejects_broad_system_prefix_exemptions(self) -> None:
        manifest = {
            "schema": 1,
            "allowed_licenses": sorted(CHECK_LICENSE.ALLOWED_LICENSES),
            "dependencies": [
                {
                    "name": "freerdp",
                    "version": "3.15.0",
                    "license": "Apache-2.0",
                    "store_patterns": ["freerdp-3.15.0"],
                    "notice": "### FreeRDP 3.15.0",
                }
            ],
            "forbidden_runtime_patterns": ["ffmpeg"],
            "system_library_prefixes": ["/usr/lib/"],
        }
        errors = CHECK_LICENSE.audit_dependency_manifest_data(
            manifest, "### FreeRDP 3.15.0\n"
        )
        self.assertTrue(any("system_library_prefixes" in error
                            for error in errors))

    def test_manifest_file_is_valid_json(self) -> None:
        manifest_path = ROOT / "release" / "dependencies.json"
        data = json.loads(manifest_path.read_text(encoding="utf-8"))
        self.assertEqual(data["schema"], 1)

    def test_notice_rejects_nonexistent_adr_path(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            errors = CHECK_LICENSE.audit_notice_links(
                root, "ADR: docs/adr/9999-does-not-exist.md.\n"
            )
            self.assertTrue(any("9999-does-not-exist.md" in error
                                for error in errors))


if __name__ == "__main__":
    unittest.main()
