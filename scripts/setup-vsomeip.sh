#!/usr/bin/env bash
# Idempotent vsomeip setup: reset the vendored submodule to its pinned
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
VSOMEIP_DIR="$REPO_ROOT/third_party/vsomeip"
PATCHES_DIR="$REPO_ROOT/patches/vsomeip"

# Install prefix: argv[1] > VSOMEIP_INSTALL_PREFIX > /usr/local. CI passes a
# job-scoped prefix (/opt/someip-stack, the build-test.yml convention) so the
# runner never overwrites a host-managed /usr/local SOME/IP stack; local dev
# keeps /usr/local. The argv form exists for sudo-restricted callers: a
# sudoers command rule without an argument list matches any argv, while
# passing VAR=val through sudo additionally requires the SETENV tag.
INSTALL_PREFIX="${1:-${VSOMEIP_INSTALL_PREFIX:-/usr/local}}"

if [[ ! -e "$VSOMEIP_DIR/.git" ]]; then
    echo "error: $VSOMEIP_DIR submodule not initialised" >&2
    echo "       run: git submodule update --init --recursive" >&2
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
# `git checkout -- .` restores modified tracked files; `git clean` drops
# files a previous apply CREATED (untracked — an extra-layer patch that adds
# files would otherwise hit "already exists / Hunk FAILED" on re-run; the
# base series never creates files, so only the OEM seam trips it). `-e
# build` keeps the build tree for an incremental rebuild.
git checkout -- .
git clean -fdxq -e build
rm -rf .pc

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
# - CMAKE_INSTALL_RPATH='$ORIGIN': libvsomeip3 dlopens its plugin modules
#   (libvsomeip3-cfg/-sd/-e2e) by bare soname from INSIDE the library, and
#   the dynamic linker does not consult the executable's DT_RUNPATH for such
#   a call — an install outside the ld.so search path (CI's job prefix)
#   would abort every app at init ("Configuration module could not be
#   loaded"). $ORIGIN makes the install self-contained: plugins and
#   co-installed deps resolve from the library's own directory.
# - CMAKE_PREFIX_PATH="$INSTALL_PREFIX": dependencies co-installed into the
#   same prefix win over system copies (CI builds Boost >= 1.75 there;
#   vsomeip 3.7.3 raised the floor past ubuntu-22.04's apt 1.74).
# - TC8_EXTRA_VSOMEIP_CMAKE_ARGS: whitespace-separated extra configure args —
#   the OEM seam mirroring TC8_EXTRA_VSOMEIP_PATCHES, e.g. the feature
#   toggle an OEM patch layer introduces. Appended last so a duplicated -D
#   overrides the defaults above. Unset => public behaviour unchanged.
extra_cmake_args=()
if [[ -n "${TC8_EXTRA_VSOMEIP_CMAKE_ARGS:-}" ]]; then
    read -r -a extra_cmake_args <<< "$TC8_EXTRA_VSOMEIP_CMAKE_ARGS"
fi
cmake -B build -DCMAKE_BUILD_TYPE=RelWithDebInfo \
      -DCMAKE_INSTALL_PREFIX="$INSTALL_PREFIX" \
      -DCMAKE_INSTALL_RPATH='$ORIGIN' \
      -DCMAKE_PREFIX_PATH="$INSTALL_PREFIX" \
      "${extra_cmake_args[@]}"
cmake --build build -j4
sudo cmake --install build

# CI runs this whole script as root (build-harness wraps it in `sudo -n` for
# the /usr/local install above), which leaves the quilt `.pc/`, the patched
# sources, and build/ root-owned. The next checkout's `git clean` runs as the
# unprivileged runner user and cannot remove a root-owned tree — git exits 128
# and blocks every future run. Restore ownership to the invoking user so the
# tree stays cleanable. No-op on a local non-sudo run (SUDO_USER unset).
if [[ -n "${SUDO_USER:-}" ]]; then
    chown -R "$SUDO_USER:$SUDO_USER" "$VSOMEIP_DIR"
fi

echo "vsomeip setup complete: $(git -C "$VSOMEIP_DIR" describe --always) -> $INSTALL_PREFIX"
