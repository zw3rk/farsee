// SPDX-License-Identifier: Apache-2.0

#ifndef FARSEE_SRC_CORE_PRIVATE_FILE_INTERNAL_H
#define FARSEE_SRC_CORE_PRIVATE_FILE_INTERNAL_H

#include "farsee/secret.h"

#include <stdbool.h>
#include <stddef.h>
#include <sys/stat.h>

typedef enum rfb_private_path_result {
    RFB_PRIVATE_PATH_OK = 0,
    RFB_PRIVATE_PATH_MISSING = 1,
    RFB_PRIVATE_PATH_INVALID = 2,
} rfb_private_path_result;

typedef struct rfb_private_path {
    int directory_fd;
    char basename[RFB_PRIVATE_FILE_PATH_CAP];
} rfb_private_path;

rfb_private_path_result rfb_private_path_open(rfb_private_path *out,
                                              const char *path,
                                              bool create_parent);
bool rfb_private_path_close(rfb_private_path *path);
bool rfb_private_directory_sync(int directory_fd);
bool rfb_private_regular_status_valid(const struct stat *status);
int rfb_private_temp_open_at(const rfb_private_path *path,
                             char *temporary_name,
                             size_t temporary_name_capacity);

#endif
