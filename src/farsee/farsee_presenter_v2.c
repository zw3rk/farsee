// SPDX-License-Identifier: Apache-2.0
//
// Farsee presenter v2 dispatch (F4 gate, §11.7).

#include "farsee/farsee_presenter_v2.h"

#include <stddef.h>

farsee_error farsee_presenter_open(farsee_presenter *p,
                                   farsee_presenter_caps *out_caps)
{
    if (p == NULL || p->ops == NULL || p->ops->open == NULL) {
        return farsee_error_make(FARSEE_ERR_STATE, FARSEE_SUB_PRESENTER,
                                 FARSEE_PHASE_NONE);
    }
    return farsee_error_make(p->ops->open(p, out_caps),
                             FARSEE_SUB_NONE, FARSEE_PHASE_NONE);
}

farsee_error farsee_presenter_present(farsee_presenter *p,
                                      const farsee_frame_commit *frame)
{
    if (p == NULL || p->ops == NULL || p->ops->present == NULL || frame == NULL) {
        return farsee_error_make(FARSEE_ERR_STATE, FARSEE_SUB_PRESENTER,
                                 FARSEE_PHASE_ACTIVE);
    }
    return farsee_error_make(p->ops->present(p, frame),
                             FARSEE_SUB_NONE, FARSEE_PHASE_ACTIVE);
}

farsee_error farsee_presenter_flush(farsee_presenter *p)
{
    if (p == NULL || p->ops == NULL || p->ops->flush == NULL) {
        return farsee_error_make(FARSEE_E_OK, FARSEE_SUB_NONE,
                                 FARSEE_PHASE_NONE);
    }
    return farsee_error_make(p->ops->flush(p),
                             FARSEE_SUB_NONE, FARSEE_PHASE_NONE);
}

void farsee_presenter_close(farsee_presenter **pp)
{
    if (pp == NULL || *pp == NULL) {
        return;
    }
    if ((*pp)->ops != NULL && (*pp)->ops->close != NULL) {
        (*pp)->ops->close(pp);
    }
}
