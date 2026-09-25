#!/usr/bin/env bash
# Idempotent vsomeip setup: reset the vsomeip source tree (the vendored
# submodule, or a consumer-owned checkout via TC8_VSOMEIP_SRC) to its pinned
# sources, apply the tc8-harness patch series (plus any OEM extension layers
# via TC8_EXTRA_VSOMEIP_PATCHES), configure (plus any OEM flags via
# TC8_EXTRA_VSOMEIP_CMAKE_ARGS), build, install.
# Usage: setup-vsomeip.sh [install-prefix]
# Run after `git submodule update --init --recursive` on a fresh clone, and
# whenever patches/vsomeip/series (or an extra layer) changes. Requires quilt
# (apt install quilt).
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"
PATCHES_DIR="$REPO_ROOT/patches/vsomeip"

# Source tree: TC8_VSOMEIP_SRC > the vendored submodule. The two seams further
# down stack layers ON a tree; neither selects it, so without this a harness pin
# bump taken for a harness reason also moves the consumer's SOME/IP base (commit
# 9e5d3c54 moved the vendored pin 3.7.1 -> 3.7.3). A consumer whose DUT is part
# of what it certifies has to pin that base itself and move it deliberately.
# The override must be a git checkout of vsomeip: the pristine reset below
# applies to it unchanged, and so does the base series — a different COVESA
# commit may fuzz or fail there, which quilt refuses loudly rather than building
# something unintended. Unset => vendored submodule => public build unchanged.
#
# ⚠ The DEFAULT is a scratch worktree, NOT the submodule itself, and that changed
# on 2026-09-25. This script RESETS, PATCHES and BUILDS IN whatever tree it is
# given, so pointing it at the submodule made a vendored checkout the build
# scratch: four tracked files stayed permanently modified there, plus quilt's
# `.pc/` and a `build/` tree. Two costs came from that, and only the second is
# about tooling. `git status` in this repository was never clean, so a real
# change inside the submodule looked exactly like the patch series. And `bx`
# could not send this repository to a build machine AT ALL — its transfer runs
# `git submodule update --force` on the far side, which resets each submodule to
# its recorded commit, so a submodule carrying deliberate local modifications can
# never satisfy the equality proof that follows. Measured on pc2: the remote
# submodule at HEAD with zero porcelain lines while this side held four modified
# files (docs/tech-debt.md TD-50).
#
# The submodule goes back to being the PIN RECORD. The worktree is git-native
# (shares the submodule's object store, costs no clone and no network), is
# recreated at the pin on every run, and is ignored so it never travels.
VSOMEIP_SCRATCH="$REPO_ROOT/.vsomeip-src"
VSOMEIP_DIR="${TC8_VSOMEIP_SRC:-$VSOMEIP_SCRATCH}"

# Stand the scratch worktree up, or move it to the pin if the submodule moved.
# Only when this run is USING it: an OEM that set TC8_VSOMEIP_SRC owns its own
# tree and must not have one built beside it.
if [[ -z "${TC8_VSOMEIP_SRC:-}" ]]; then
    SUBMODULE_DIR="$REPO_ROOT/third_party/vsomeip"
    if [[ ! -e "$SUBMODULE_DIR/.git" ]]; then
        echo "error: $SUBMODULE_DIR submodule not initialised" >&2
        echo "       run: git submodule update --init --recursive" >&2
        exit 1
    fi
    # The pin is whatever the submodule is checked out at — read it from there
    # rather than from `git ls-tree` on the superproject, so a deliberate local
    # submodule bump under test is honoured the same way it always was.
    SM_HEAD="$(git -C "$SUBMODULE_DIR" rev-parse HEAD)"
    if [[ -e "$VSOMEIP_SCRATCH/.git" ]]; then
        # Detached and forced: this tree is ours, it holds no work of anyone's,
        # and the reset below restores it anyway.
        git -C "$VSOMEIP_SCRATCH" checkout --detach --force -q "$SM_HEAD"
    else
        # `--force` so a leftover registration from a removed directory (a
        # `git clean -fdx` at repo level takes the tree but not the record)
        # does not refuse the add. `prune` first is the git-native way to say it.
        git -C "$SUBMODULE_DIR" worktree prune
        rm -rf "$VSOMEIP_SCRATCH"
        git -C "$SUBMODULE_DIR" worktree add --detach --force -q \
            "$VSOMEIP_SCRATCH" "$SM_HEAD"
    fi
fi

# Install prefix: argv[1] > VSOMEIP_INSTALL_PREFIX > /usr/local. CI passes a
# job-scoped prefix (/opt/someip-stack, the build-test.yml convention) so the
# runner never overwrites a host-managed /usr/local SOME/IP stack; local dev
# keeps /usr/local. The argv form exists for sudo-restricted callers: a
# sudoers command rule without an argument list matches any argv, while
# passing VAR=val through sudo additionally requires the SETENV tag.
INSTALL_PREFIX="${1:-${VSOMEIP_INSTALL_PREFIX:-/usr/local}}"

if [[ -n "${TC8_VSOMEIP_SRC:-}" ]]; then
    if [[ ! -d "$VSOMEIP_DIR" ]]; then
        echo "error: TC8_VSOMEIP_SRC is not a directory: $VSOMEIP_DIR" >&2
        exit 1
    fi
    # Absolutise: this script cd's into the tree, and the chown + `git describe`
    # at the end address it again from that new cwd, so a relative override would
    # resolve somewhere else there.
    VSOMEIP_DIR="$(cd "$VSOMEIP_DIR" && pwd)"
    # The pristine reset below runs `git clean -fdx` in this tree, deleting every
    # untracked file in it. Refuse that on a tree that is not vsomeip: a mistyped
    # override pointing at another checkout would otherwise destroy work before a
    # patch or build failure could surface the mistake.
    if [[ ! -e "$VSOMEIP_DIR/CMakeLists.txt" || ! -d "$VSOMEIP_DIR/interface/vsomeip" ]]; then
        echo "error: TC8_VSOMEIP_SRC does not look like a vsomeip checkout: $VSOMEIP_DIR" >&2
        echo "       expected CMakeLists.txt and interface/vsomeip/ in it" >&2
        exit 1
    fi
fi

if [[ ! -e "$VSOMEIP_DIR/.git" ]]; then
    if [[ -n "${TC8_VSOMEIP_SRC:-}" ]]; then
        echo "error: TC8_VSOMEIP_SRC is not a git checkout: $VSOMEIP_DIR" >&2
        echo "       the pristine reset needs git checkout/clean to restore the tree" >&2
    else
        echo "error: $VSOMEIP_DIR submodule not initialised" >&2
        echo "       run: git submodule update --init --recursive" >&2
    fi
    exit 1
fi
if ! command -v quilt >/dev/null; then
    echo "error: quilt not installed (sudo apt install quilt)" >&2
    exit 1
fi

cd "$VSOMEIP_DIR"

# Restore pristine pinned sources before re-applying the stack, then drop
# quilt's bookkeeping so the merged series always applies from scratch. Two
# desync shapes make anything less than a full reset unreliable:
#   - CI: `actions/checkout`'s submodule sync reverts tracked files but
#     leaves the untracked `.pc/` behind, so quilt believes the series is
#     applied while the sources are pristine (`quilt push -a` exits 2).
#   - local: a prior run leaves patched sources whose staged merged series
#     (a mktemp dir) is gone, so quilt cannot pop and a bare re-push hits
#     reversed-patch failures.
# `git checkout -- .` restores modified tracked files; `git clean -fdx` drops
# ALL untracked — including quilt's `.pc/` bookkeeping AND files a previous apply
# CREATED (an extra-layer patch that adds files would otherwise hit "already
# exists / Hunk FAILED" on re-run; the base series creates none, so only the OEM
# seam trips it). `-e build` keeps the build tree for an incremental rebuild.
git checkout -- .
git clean -fdxq -e build

# Apply the tc8-harness base patch series, then any OEM extension layers stacked
# on top, as ONE quilt stack. TC8_EXTRA_VSOMEIP_PATCHES is a ':'-separated list
# of patch dirs (each with its own `series`), mirroring CMake's TC8_EXTRA_CASE_DIRS
# for case discovery: an OEM stacks private patches from its own repo without ever
# editing this base series. ':' (shell PATH-style) is the separator here, vs ';'
# for the CMake list seams. Unset => base only => public behaviour byte-identical.
#
# quilt assumes a single series per tree, so the base + extra series are merged into
# one staging dir (base first, each extra under its own oemN/ subdir so identical
# patch filenames across layers cannot collide) and `quilt push -a` runs once.
STAGE="$(mktemp -d)"
trap 'rm -rf "$STAGE"' EXIT
: > "$STAGE/series"

stage_series() {  # $1 = source patches dir (with a `series`); $2 = stage subdir tag
    local src="$1" tag="$2" line patch rest
    [[ -s "$src/series" ]] || return 0
    while IFS= read -r line || [[ -n "$line" ]]; do
        line="${line%%#*}"               # drop comments
        read -r patch rest <<< "$line"   # first token = patch path, rest = quilt opts
        [[ -n "$patch" ]] || continue    # skip blank / comment-only lines
        if [[ ! -f "$src/$patch" ]]; then
            echo "error: patch '$patch' listed in $src/series not found under $src" >&2
            exit 1
        fi
        mkdir -p "$STAGE/$tag/$(dirname "$patch")"
        cp "$src/$patch" "$STAGE/$tag/$patch"
        printf '%s%s\n' "$tag/$patch" "${rest:+ $rest}" >> "$STAGE/series"
    done < "$src/series"
}

stage_series "$PATCHES_DIR" base

if [[ -n "${TC8_EXTRA_VSOMEIP_PATCHES:-}" ]]; then
    extra_idx=0
    IFS=':' read -ra extra_patch_dirs <<< "$TC8_EXTRA_VSOMEIP_PATCHES"
    for extra_dir in "${extra_patch_dirs[@]}"; do
        [[ -n "$extra_dir" ]] || continue
        if [[ ! -d "$extra_dir" ]]; then
            echo "error: TC8_EXTRA_VSOMEIP_PATCHES entry is not a directory: $extra_dir" >&2
            exit 1
        fi
        stage_series "$extra_dir" "oem$extra_idx"
        extra_idx=$((extra_idx + 1))
    done
fi

# Empty merged series is a no-op (no patches in the base or any extra layer).
if [[ -s "$STAGE/series" ]]; then
    QUILT_PATCHES="$STAGE" quilt push -a
fi

# Build + install. Cap parallelism per repo policy.
#
# - CMAKE_INSTALL_RPATH='$ORIGIN:$ORIGIN/../lib': libvsomeip3 dlopens its
#   plugin modules (libvsomeip3-cfg/-sd/-e2e) by bare soname from INSIDE the
#   library, and the dynamic linker does not consult the executable's
#   DT_RUNPATH for such a call — an install outside the ld.so search path
#   (CI's job prefix) would abort every app at init ("Configuration module
#   could not be loaded"). $ORIGIN resolves the plugins + co-installed deps
#   from a library's own dir (lib/); $ORIGIN/../lib additionally lets vsomeip's
#   own installed executables in bin/ (routingmanagerd et al.) find lib/, so
#   the whole install is self-contained regardless of which dir a binary sits
#   in. One value covers both target kinds.
# - CMAKE_PREFIX_PATH="$INSTALL_PREFIX": dependencies co-installed into the
#   same prefix win over system copies (CI builds Boost >= 1.75 there;
#   vsomeip 3.7.3 raised the floor past ubuntu-22.04's apt 1.74).
# - TC8_EXTRA_VSOMEIP_CMAKE_ARGS: whitespace-separated extra configure args —
#   the OEM seam mirroring TC8_EXTRA_VSOMEIP_PATCHES, e.g. the feature
#   toggle an OEM patch layer introduces, or an ENABLE_TC8_* gate a base
#   patch introduces that a consumer's own specification forbids (the two
#   seams are additive, so declining a base patch happens through the gate
#   rather than by removing the patch — README, "Declining a base-patch
#   behaviour"). Appended last so a duplicated -D overrides the defaults
#   above. Unset => public behaviour unchanged.
extra_cmake_args=()
if [[ -n "${TC8_EXTRA_VSOMEIP_CMAKE_ARGS:-}" ]]; then
    read -r -a extra_cmake_args <<< "$TC8_EXTRA_VSOMEIP_CMAKE_ARGS"
fi
# Content-addressed compiler cache when ccache is on PATH. ccache keys each
# object on the preprocessed source + flags, so rebuilding after the CI checkout
# wiped build/ (git clean runs before every run) is a cache hit rather than a
# cold recompile — identical output, purely a wall-clock win. Omitted when ccache
# is absent so a local or OEM build without it is byte-for-byte unchanged. Under
# CI this runs as root (sudo), so its store is /root/.cache/ccache, disjoint from
# the unprivileged harness build's ~/.cache/ccache; the two compile different
# sources and never contend. Placed before extra_cmake_args so an OEM -D still
# wins (it can even override the launcher, matching that seam's documented rule).
ccache_args=()
if command -v ccache >/dev/null 2>&1; then
    ccache_args=(-DCMAKE_C_COMPILER_LAUNCHER=ccache
                 -DCMAKE_CXX_COMPILER_LAUNCHER=ccache)
fi
cmake -B build -DCMAKE_BUILD_TYPE=RelWithDebInfo \
      -DCMAKE_INSTALL_PREFIX="$INSTALL_PREFIX" \
      -DCMAKE_INSTALL_RPATH='$ORIGIN:$ORIGIN/../lib' \
      -DCMAKE_PREFIX_PATH="$INSTALL_PREFIX" \
      "${ccache_args[@]}" \
      "${extra_cmake_args[@]}"
cmake --build build -j4
# Install with sudo only when we are not already root. The script is
# routinely run as root (CI wraps it in `sudo -n`, and the comment below
# depends on that), and in that mode `sudo` adds nothing but a dependency —
# one a minimal root environment such as a container image does not have,
# where the unconditional call failed with `sudo: command not found` after a
# complete build. Non-root callers are unaffected.
if [[ $EUID -eq 0 ]]; then
    cmake --install build
else
    sudo cmake --install build
fi

# CI runs this whole script as root (build-harness wraps it in `sudo -n` for
# the /usr/local install above), which leaves the quilt `.pc/`, the patched
# sources, and build/ root-owned. The next checkout's `git clean` runs as the
# unprivileged runner user and cannot remove a root-owned tree — git exits 128
# and blocks every future run. Restore ownership to the invoking user so the
# tree stays cleanable. No-op on a local non-sudo run (SUDO_USER unset).
if [[ -n "${SUDO_USER:-}" ]]; then
    chown -R "$SUDO_USER:$SUDO_USER" "$VSOMEIP_DIR"
fi

# Name the source tree too when it is not the vendored one: which vsomeip commit
# a DUT was built from is evidence a consumer has to be able to state, and this
# line is what a build log carries.
echo "vsomeip setup complete: $(git -C "$VSOMEIP_DIR" describe --always)${TC8_VSOMEIP_SRC:+ (source: $VSOMEIP_DIR)} -> $INSTALL_PREFIX"
