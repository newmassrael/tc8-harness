#!/usr/bin/env bash
# Print the CMake compiler-launcher arguments that route this repository's compiles
# through ccache, one argument per line, or nothing when ccache is not on PATH (a
# build without it is then byte-for-byte unchanged).
#
#   mapfile -t ccache_args < <(scripts/ccache-launcher.sh)
#   cmake -S . -B build ... "${ccache_args[@]}"
#
# WHY ONE SCRIPT. Every harness build that wants the cache needs the same three
# settings, and before this script they reached ccache through the job's
# environment (exported by one CI step and inherited by the next) or through the
# build host's own ~/.config/ccache/ccache.conf. A host-level setting is invisible to
# the repository: the smoke runner moved to a machine without that file on
# 2026-11-02, and its "warm" build took 18m53s against 19m15s cold. So the settings
# are carried by the launcher itself (`env K=V ... ccache`), which CMake stores in
# the build tree. Every later build of that tree caches the same way, whoever runs
# it and whatever its environment.
#
# THE SETTINGS.
#
#   CCACHE_DEPEND=1 — depend mode: ccache takes a compile's inputs from the
#   compiler's own -MD output instead of running the preprocessor and parsing its
#   line markers. The SCE generator writes `#line N "<case>.scxml"` into every
#   generated state machine (.inl), naming the SCXML by its bare file name. In the
#   default mode ccache lstat()s every file a line marker names, cannot find
#   `arp_40.scxml` relative to the build directory, and gives up on the compile
#   (`bad_input_file`). Measured on the runner: every case-registration unit, 31
#   compiles a build and the heaviest in the tree, was recompiled from scratch on
#   every run; in depend mode one such unit went from 83 s to a 0 s hit. Depend mode
#   needs -MD, which CMake's Makefile and Ninja generators always pass.
#
#   CCACHE_BASEDIR=<repository root> — lets hits cross checkouts. Without it every
#   -I is an absolute path under the checkout, so the runner's entries and a
#   developer tree's entries for the identical commit are distinct. ccache rewrites
#   paths beneath the base directory to relative before hashing. It pairs with the
#   generated case stubs including their traits header by a RELATIVE path
#   (src/harness/CMakeLists.txt): the base directory normalises the command line,
#   that normalises the source text, and a direct-mode hit needs both.
#
#   CCACHE_NOHASHDIR=1 — drops the build directory from the hash, for the same
#   reason. Safe here because these are Release objects with no debug information to
#   carry a stale path.
set -euo pipefail

command -v ccache >/dev/null 2>&1 || exit 0

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
launcher="env;CCACHE_DEPEND=1;CCACHE_BASEDIR=${repo_root};CCACHE_NOHASHDIR=1;ccache"
printf '%s\n' "-DCMAKE_C_COMPILER_LAUNCHER=${launcher}" "-DCMAKE_CXX_COMPILER_LAUNCHER=${launcher}"
