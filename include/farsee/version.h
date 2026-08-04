// SPDX-License-Identifier: Apache-2.0
//
// farsee version string (plan.md §G12 "version output and protocol
// capability output"; introduced minimally in G0 so the build-system
// smoke test has something concrete to link against).

#ifndef FARSEE_INCLUDE_FARSEE_VERSION_H
#define FARSEE_INCLUDE_FARSEE_VERSION_H

#ifdef __cplusplus
extern "C" {
#endif

// Project version, dotted. Stable for a release; `-dev` between releases.
#define FARSEE_VERSION_MAJOR 0
#define FARSEE_VERSION_MINOR 1
#define FARSEE_VERSION_PATCH 0
#define FARSEE_VERSION_SUFFIX "-dev"
#define FARSEE_VERSION_STRING "0.1.0-dev"

// Returns the human-readable version string used by --version.
const char *farsee_version_string(void);

// Returns the canonical project name ("farsee").
const char *farsee_project_name(void);

#ifdef __cplusplus
}
#endif

#endif  // FARSEE_INCLUDE_FARSEE_VERSION_H
