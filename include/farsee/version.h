// SPDX-License-Identifier: Apache-2.0
//
// farsee — project version constants and accessors.
//
// The constants and accessors expose the version and project name.

#ifndef FARSEE_INCLUDE_FARSEE_VERSION_H
#define FARSEE_INCLUDE_FARSEE_VERSION_H

#ifdef __cplusplus
extern "C" {
#endif

// Project version, dotted. Stable for a release; `-dev` between releases.
#ifndef FARSEE_VERSION_MAJOR
#define FARSEE_VERSION_MAJOR 0
#endif
#ifndef FARSEE_VERSION_MINOR
#define FARSEE_VERSION_MINOR 1
#endif
#ifndef FARSEE_VERSION_PATCH
#define FARSEE_VERSION_PATCH 0
#endif
#ifndef FARSEE_VERSION_SUFFIX
#define FARSEE_VERSION_SUFFIX "-dev"
#endif
#ifndef FARSEE_VERSION_STRING
#define FARSEE_VERSION_STRING "0.1.0-dev"
#endif

// Returns the human-readable version string used by --version.
const char *farsee_version_string(void);

// Returns the canonical project name ("farsee").
const char *farsee_project_name(void);

#ifdef __cplusplus
}
#endif

#endif  // FARSEE_INCLUDE_FARSEE_VERSION_H
