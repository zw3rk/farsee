# SPDX-License-Identifier: Apache-2.0
"""Guard the Windows interoperability guest against password expiry."""

from __future__ import annotations

from pathlib import Path
import unittest


ROOT = Path(__file__).resolve().parents[2]
ACCOUNT = "TestAdmin"
NONEXPIRING_COMMAND = (
    "Set-LocalUser -Name 'TestAdmin' -PasswordNeverExpires $true"
)


def provisions_nonexpiring_test_account(text: str) -> bool:
    """Return true only for the account-specific non-expiry command."""
    return NONEXPIRING_COMMAND in text


class WindowsVmProvisioningTests(unittest.TestCase):
    def test_unrelated_or_absent_account_command_is_rejected(self) -> None:
        self.assertFalse(provisions_nonexpiring_test_account(""))
        self.assertFalse(
            provisions_nonexpiring_test_account(
                "Set-LocalUser -Name 'Other' -PasswordNeverExpires $true"
            )
        )

    def test_unattended_install_keeps_lab_account_password_nonexpiring(
        self,
    ) -> None:
        answer = (ROOT / "tools/windows-vm/Autounattend.xml").read_text(
            encoding="utf-8"
        )
        self.assertTrue(provisions_nonexpiring_test_account(answer))

    def test_direct_deploy_keeps_lab_account_password_nonexpiring(self) -> None:
        deploy = (ROOT / "tools/windows-vm/deploy.cmd").read_text(
            encoding="utf-8"
        )
        self.assertTrue(provisions_nonexpiring_test_account(deploy))


if __name__ == "__main__":
    unittest.main()
