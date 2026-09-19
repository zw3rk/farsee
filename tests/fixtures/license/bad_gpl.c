// SPDX-License-Identifier: GPL-3.0-or-later
//
// License-checker fixture: the "bad" sample. This file carries a
// prohibited GPL-family SPDX identifier and is NOT compiled or linked
// into any artifact. It exists only so tools/check_license.py can prove
// it rejects such an identifier. See plan.md §G0, §5.3.
//
// No actual GPL source is reproduced here; this is a header sentinel
// the auditor is trained to flag.

int license_fixture_bad_symbol(void)
{
    return 0;
}
