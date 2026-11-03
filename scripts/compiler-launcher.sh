#!/usr/bin/env bash
# The compiler launcher of every harness build (CMAKE_C_COMPILER_LAUNCHER and
# CMAKE_CXX_COMPILER_LAUNCHER, which scripts/compiler-launcher-args.sh prints). CMake
# runs it once per compile with the compiler's command line as its arguments, and it
# picks the cache for THAT compile from the environment the build runs in:
#
#   1. the bx run's own sccache server, when the run has one listening;
#   2. otherwise ccache, when it is on PATH, with the settings below;
#   3. otherwise the compiler itself.
#
# WHY PER COMPILE, NOT PER CONFIGURE. CMake stores the launcher in the build tree, and
# the tree outlives the run that configured it. A launcher that named the run's sccache
# would, in a later build of the same tree where no server is up, start a server of its
# own on the machine's shared port and local disk, which is what a run's own server
# exists to avoid (bx, "THE RUN'S COMPILER CACHE"). What the tree stores is this script;
# the choice is made where the compile happens.
#
# 1. THE RUN'S SCCACHE. bx starts an sccache server inside a run's unit when the machine
# has a shared compiler-cache store, so one compile's result serves every fleet machine.
# Its contract, read off bx-agent's unit.rs: when the server listens, SCCACHE_SERVER_UDS
# names its socket and RUSTC_WRAPPER names the exact sccache binary that started it (bx's
# pinned release, not a distro copy without the store backend); when it does not,
# RUSTC_WRAPPER is empty. bx names that binary only in the Rust variable, so it is read
# here, and only together with a live socket. Measured 2026-11-03: a remote harness
# build without this made 0 requests to the run's server and compiled 58 minutes cold.
# Hits are shared between checkouts at the same path; bx gives a slot the same path on
# every machine, and a different slot misses, because the path is part of the key and
# the server's base directories are bx's configuration, not the build's.
#
# 2. CCACHE, AND ITS THREE SETTINGS. They are carried here rather than in the job's
# environment or the machine's ~/.config/ccache/ccache.conf: a setting of the machine
# is invisible to the repository, and when the smoke runner moved to a machine without
# that file on 2026-11-02 its "warm" build took 18m53s against 19m15s cold.
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
#
# ccache does not see the launcher, only the compiler's command line, so moving the
# settings from an `env K=V ccache` launcher into this script keeps every existing
# entry valid.
set -eu

if [[ -n "${SCCACHE_SERVER_UDS:-}" && -S "${SCCACHE_SERVER_UDS}" \
      && "${RUSTC_WRAPPER:-}" == */sccache && -x "${RUSTC_WRAPPER}" ]]; then
    exec "${RUSTC_WRAPPER}" "$@"
fi

if command -v ccache >/dev/null 2>&1; then
    # compiler-launcher-args.sh gives CMake this script's absolute path, so the
    # repository root is a string operation and costs a compile no extra process.
    self="${BASH_SOURCE[0]}"
    if [[ "${self}" == /*/scripts/compiler-launcher.sh ]]; then
        repo_root="${self%/scripts/compiler-launcher.sh}"
    else
        repo_root="$(cd "$(dirname "${self}")/.." && pwd)"
    fi
    export CCACHE_DEPEND=1 CCACHE_BASEDIR="${repo_root}" CCACHE_NOHASHDIR=1
    exec ccache "$@"
fi

exec "$@"
