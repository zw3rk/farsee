// SPDX-License-Identifier: Apache-2.0
// Apple post-auth message parser fuzz target.
//
// Feeds arbitrary bytes into the apple_postauth parsers to prove they
// never crash, leak, or read out of bounds on malformed/truncated input.
// The parsers must always return a typed error or RFB_OK — never abort.

#include "farsee/apple_postauth.h"

#include <stdint.h>
#include <string.h>

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size);
int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
    // ServerInit parser.
    apple_server_init si;
    (void)apple_postauth_parse_server_init(data, size, &si);

    // ViewerInfo parser.
    apple_viewer_info vi;
    (void)apple_postauth_parse_viewer_info(data, size, &vi);

    // DisplayConfig parser.
    apple_display_config dc;
    (void)apple_postauth_parse_display_config(data, size, &dc);

    return 0;
}
