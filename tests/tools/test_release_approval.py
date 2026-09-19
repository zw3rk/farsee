# SPDX-License-Identifier: Apache-2.0
"""Tests for the machine-enforced release approval record."""

from __future__ import annotations

import importlib.util
from pathlib import Path
import subprocess
import tempfile
import unittest


ROOT = Path(__file__).resolve().parents[2]
SPEC = importlib.util.spec_from_file_location(
    "check_release_approval", ROOT / "tools/check_release_approval.py"
)
assert SPEC is not None and SPEC.loader is not None
AUDIT = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(AUDIT)


def approved_record() -> dict:
    return {
        "schema": 2,
        "status": "approved",
        "candidate_revision": "a" * 40,
        "candidate_version": "1.2.3-rc1",
        "owner_release_approval": approved_decision("owner-record"),
        "apple_provenance_approval": approved_decision("provenance-record"),
        "independent_review_approval": approved_decision("review-record"),
        "signing_identity_approval": approved_decision("signing-record"),
    }


def approved_decision(evidence: str) -> dict:
    return {
        "approved": True,
        "approver": "release-reviewer",
        "approved_on": "2026-09-19",
        "evidence": evidence,
    }


def blocked_decision() -> dict:
    return {
        "approved": False,
        "approver": None,
        "approved_on": None,
        "evidence": None,
    }


class ReleaseApprovalTests(unittest.TestCase):
    def test_complete_approval_record_passes(self) -> None:
        self.assertEqual(
            AUDIT.audit(approved_record(), expected_version="1.2.3-rc1"), []
        )

    def test_blocked_record_fails_every_required_approval(self) -> None:
        record = approved_record()
        record.update(
            status="blocked",
            owner_release_approval=blocked_decision(),
            apple_provenance_approval=blocked_decision(),
            independent_review_approval=blocked_decision(),
            signing_identity_approval=blocked_decision(),
        )
        errors = AUDIT.audit(record)
        self.assertEqual(len(errors), 5)
        self.assertTrue(any("status" in error for error in errors))
        for field in AUDIT.APPROVAL_FIELDS:
            self.assertTrue(any(field in error for error in errors))

    def test_missing_extra_and_nonboolean_fields_fail_closed(self) -> None:
        record = approved_record()
        del record["owner_release_approval"]
        self.assertTrue(AUDIT.audit(record))

        record = approved_record()
        record["unexpected"] = True
        self.assertTrue(AUDIT.audit(record))

        record = approved_record()
        record["owner_release_approval"] = {"approved": 1}
        self.assertTrue(AUDIT.audit(record))

    def test_schema_and_status_are_exact(self) -> None:
        for key, value in (("schema", 1), ("status", "APPROVED")):
            record = approved_record()
            record[key] = value
            with self.subTest(key=key, value=value):
                self.assertTrue(AUDIT.audit(record))

    def test_candidate_identity_is_exact_and_version_bound(self) -> None:
        record = approved_record()
        record["candidate_revision"] = "abc123"
        self.assertTrue(AUDIT.audit(record))

        record = approved_record()
        record["candidate_version"] = "1.2.3 rc1"
        self.assertTrue(AUDIT.audit(record))

        self.assertTrue(
            AUDIT.audit(approved_record(), expected_version="1.2.4")
        )

    def test_approved_decisions_require_attribution_date_and_evidence(self) -> None:
        for field in ("approver", "approved_on", "evidence"):
            record = approved_record()
            record["owner_release_approval"][field] = ""
            with self.subTest(field=field):
                self.assertTrue(AUDIT.audit(record))

        record = approved_record()
        record["owner_release_approval"]["approved_on"] = "19-09-2026"
        self.assertTrue(AUDIT.audit(record))

    def test_blocked_decisions_cannot_carry_approval_metadata(self) -> None:
        record = approved_record()
        decision = blocked_decision()
        decision["evidence"] = "misleading-record"
        record["owner_release_approval"] = decision
        errors = AUDIT.audit(record)
        self.assertTrue(any("metadata" in error for error in errors))

    def test_only_approval_record_may_follow_bound_candidate(self) -> None:
        self.assertEqual(AUDIT.audit_candidate_paths([]), [])
        self.assertEqual(
            AUDIT.audit_candidate_paths(["release/approval.json"]), []
        )
        self.assertTrue(AUDIT.audit_candidate_paths(["src/app/main.c"]))
        self.assertTrue(
            AUDIT.audit_candidate_paths(
                ["release/approval.json", "CHANGELOG.md"]
            )
        )

    def test_candidate_source_check_allows_only_the_approval_record(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            repo = Path(raw)
            subprocess.run(["git", "init", "-q", repo], check=True)
            source = repo / "source.c"
            source.write_text("int source(void) { return 0; }\n", encoding="utf-8")
            subprocess.run(["git", "-C", repo, "add", "source.c"], check=True)
            subprocess.run(
                [
                    "git", "-C", repo,
                    "-c", "user.name=Release Test",
                    "-c", "user.email=release-test@example.invalid",
                    "commit", "-q", "-m", "Create candidate",
                ],
                check=True,
            )
            revision = subprocess.run(
                ["git", "-C", repo, "rev-parse", "HEAD"],
                check=True,
                capture_output=True,
                text=True,
            ).stdout.strip()

            self.assertEqual(AUDIT.audit_candidate_source(repo, revision), [])
            approval = repo / "release" / "approval.json"
            approval.parent.mkdir()
            approval.write_text("{}\n", encoding="utf-8")
            self.assertEqual(AUDIT.audit_candidate_source(repo, revision), [])

            source.write_text("int source(void) { return 1; }\n", encoding="utf-8")
            errors = AUDIT.audit_candidate_source(repo, revision)
            self.assertTrue(any("source.c" in error for error in errors))


if __name__ == "__main__":
    unittest.main()
