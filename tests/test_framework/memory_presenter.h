// SPDX-License-Identifier: Apache-2.0
// Test-only in-memory presenter for framebuffer and lifecycle assertions.

#ifndef FARSEE_TESTS_TEST_FRAMEWORK_MEMORY_PRESENTER_H
#define FARSEE_TESTS_TEST_FRAMEWORK_MEMORY_PRESENTER_H

#include "farsee/presenter.h"

#include <stddef.h>
#include <stdint.h>

typedef struct rfb_test_memory_presenter {
    uint8_t *storage;
    size_t capacity;
    size_t size;
    uint32_t width;
    uint32_t height;
    uint32_t stride;
    unsigned open_count;
    unsigned resize_count;
    unsigned present_count;
    unsigned close_count;
} rfb_test_memory_presenter;

void rfb_test_memory_presenter_init(rfb_test_memory_presenter *presenter,
                                    uint8_t *storage, size_t capacity);

extern const rfb_presenter_ops rfb_test_memory_presenter_ops;

#endif  // FARSEE_TESTS_TEST_FRAMEWORK_MEMORY_PRESENTER_H
