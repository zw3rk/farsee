#!/bin/sh
# SPDX-License-Identifier: Apache-2.0
#
# Shim that makes llvm-cov behave like gcov for lcov's --gcov-tool option.
# lcov invokes the tool as `<tool> <args...> <file.gcda>` expecting gcov
# semantics; llvm-cov requires the `gcov` subcommand: `llvm-cov gcov ...`.
# This wrapper inserts the subcommand transparently.
exec llvm-cov gcov "$@"
