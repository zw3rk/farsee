// SPDX-License-Identifier: Apache-2.0
//
// R5 — RDP clipboard bridge tests (§15.13, §13.3).

#ifdef FARSEE_WITH_RDP

#include "protocol/rdp/rdp_clipboard_bridge.h"
#include "tests/test_framework/rfb_test.h"

RFB_TEST(rdp_clip, inbound__disabled_rejects_dir)
{
    farsee_clip_policy p = farsee_clip_policy_default();  // DISABLED
    RFB_CHECK(rdp_clip_check_inbound(&p, 10, FARSEE_CLIP_FORMAT_UTF8_TEXT) ==
              RDP_CLIP_REJECT_DIR);
}

RFB_TEST(rdp_clip, inbound__allowed_under_size_cap)
{
    farsee_clip_policy p = farsee_clip_policy_default();
    p.direction = FARSEE_CLIP_DIRECTION_REMOTE_TO_LOCAL;
    RFB_CHECK(rdp_clip_check_inbound(&p, 100, FARSEE_CLIP_FORMAT_UTF8_TEXT) ==
              RDP_CLIP_ALLOW);
    // Over the 1 MiB cap.
    RFB_CHECK(rdp_clip_check_inbound(&p, (1024u*1024u)+1, FARSEE_CLIP_FORMAT_UTF8_TEXT) ==
              RDP_CLIP_REJECT_SIZE);
}

RFB_TEST(rdp_clip, inbound__non_text_format_rejected)
{
    farsee_clip_policy p = farsee_clip_policy_default();
    p.direction = FARSEE_CLIP_DIRECTION_BIDIRECTIONAL;
    // No rich/file formats in scope (§13.3); cast to satisfy the enum type.
    RFB_CHECK(rdp_clip_check_inbound(&p, 10, (farsee_clip_format)999) ==
              RDP_CLIP_REJECT_FMT);
}

RFB_TEST(rdp_clip, inbound__wrong_direction_rejected)
{
    farsee_clip_policy p = farsee_clip_policy_default();
    p.direction = FARSEE_CLIP_DIRECTION_LOCAL_TO_REMOTE;  // outbound only
    RFB_CHECK(rdp_clip_check_inbound(&p, 10, FARSEE_CLIP_FORMAT_UTF8_TEXT) ==
              RDP_CLIP_REJECT_DIR);
}

RFB_TEST(rdp_clip, outbound__respects_direction_and_size)
{
    farsee_clip_policy p = farsee_clip_policy_default();
    p.direction = FARSEE_CLIP_DIRECTION_LOCAL_TO_REMOTE;
    RFB_CHECK(rdp_clip_allows_outbound(&p, 100));
    RFB_CHECK(rdp_clip_allows_outbound(&p, (1024u*1024u)+1) == false);
    p.direction = FARSEE_CLIP_DIRECTION_REMOTE_TO_LOCAL;  // inbound only
    RFB_CHECK(rdp_clip_allows_outbound(&p, 100) == false);
}

#endif  // FARSEE_WITH_RDP
