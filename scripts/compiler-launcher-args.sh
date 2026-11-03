#!/usr/bin/env bash
# Print the CMake arguments that make scripts/compiler-launcher.sh the launcher of
# every C and C++ compile, one argument per line:
#
#   mapfile -t launcher_args < <(scripts/compiler-launcher-args.sh)
#   cmake -S . -B build ... "${launcher_args[@]}"
#
# The launcher decides per compile which cache to use (the bx run's sccache, ccache,
# or none) and says why; this script only points CMake at it, with an absolute path
# so the launcher finds its repository without a process of its own. Every build that
# compiles this tree configures through here: the shared CI action, the suite
# producer ratchet and the commands in bx.toml.
set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
launcher="${repo_root}/scripts/compiler-launcher.sh"
printf '%s\n' "-DCMAKE_C_COMPILER_LAUNCHER=${launcher}" "-DCMAKE_CXX_COMPILER_LAUNCHER=${launcher}"
