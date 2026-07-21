// SPDX-License-Identifier: Apache-2.0
//
// farsee — dump presenter (plan.md §G3, §10.5).
//
// Writes the canonical RGBA8 framebuffer to a file on each present. Also
// optionally writes a PPM (P6) for human inspection. Used by golden-image
// tests and the `--dump-frame` CLI option.

#include "farsee/presenter.h"

#include <stdio.h>
#include <string.h>

void rfb_presenter_dump_init(rfb_presenter_dump *d, const char *path,
                             bool write_ppm)
{
    if (d != NULL) {
        d->path = path;
        d->write_ppm = write_ppm;
        d->present_count = 0;
    }
}

static int dump_present(void *ctx, const rfb_framebuffer *fb,
                        const rfb_damage_batch *damage)
{
    rfb_presenter_dump *d = (rfb_presenter_dump *)ctx;
    if (d == NULL || d->path == NULL || fb == NULL || fb->rgba == NULL) {
        return -1;
    }
    // Write raw RGBA.
    FILE *f = fopen(d->path, "wb");
    if (f == NULL) {
        return -1;
    }
    size_t total = (size_t)fb->height * fb->stride;
    size_t wrote = fwrite(fb->rgba, 1, total, f);
    fclose(f);
    if (wrote != total) {
        return -1;
    }
    // Optional PPM (P6 is binary RGB; we drop the alpha channel).
    if (d->write_ppm) {
        // Compose a "<path>.ppm" filename. Bound to the caller's path
        // length; assume the caller leaves room.
        char ppm_path[1024];
        int n = snprintf(ppm_path, sizeof ppm_path, "%s.ppm", d->path);
        if (n <= 0 || (size_t)n >= sizeof ppm_path) {
            // Path too long; skip PPM rather than truncate.
            d->present_count++;
            (void)damage;
            return 0;
        }
        FILE *pf = fopen(ppm_path, "wb");
        if (pf == NULL) {
            d->present_count++;
            return 0;  // PPM is best-effort
        }
        fprintf(pf, "P6\n%u %u\n255\n",
                (unsigned)fb->width, (unsigned)fb->height);
        // Write RGB only.
        for (size_t i = 0; i < total; i += 4) {
            uint8_t rgb[3] = { fb->rgba[i], fb->rgba[i + 1], fb->rgba[i + 2] };
            (void)fwrite(rgb, 1, 3, pf);
        }
        fclose(pf);
    }
    d->present_count++;
    (void)damage;
    return 0;
}

static void dump_close(void *ctx)
{
    (void)ctx;
}

const rfb_presenter_ops rfb_presenter_dump_ops = {
    .open    = NULL,
    .resize  = NULL,
    .present = dump_present,
    .close   = dump_close,
};
