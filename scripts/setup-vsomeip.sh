#!/usr/bin/env bash
# Idempotent vsomeip setup: apply the tc8-harness patch series (plus any OEM
# extension layers via TC8_EXTRA_VSOMEIP_PATCHES), build, install.
# Run after `git submodule update --init --recursive` on a fresh clone, and
# whenever patches/vsomeip/series (or an extra layer) changes. Requires quilt
# (apt install quilt).
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"
VSOMEIP_DIR="$REPO_ROOT/third_party/vsomeip"
PATCHES_DIR="$REPO_ROOT/patches/vsomeip"

# Install prefix is overridable so CI can co-locate vsomeip with
# CommonAPI under /opt/someip-stack (build-test.yml convention) while
# local dev defaults to /usr/local.
INSTALL_PREFIX="${VSOMEIP_INSTALL_PREFIX:-/usr/local}"

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

# `actions/checkout` 's submodule update reverts tracked files to the
# pinned commit but leaves untracked `.pc/` (quilt's bookkeeping)
# behind across CI runs. That desyncs quilt's "what's applied" view
# from the actual file contents, so a subsequent `quilt push -a`
# reports "File series fully applied" and exits 2 (which then trips
# `set -e`). Nuking `.pc/` forces a clean reapply every time.
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
cmake -B build -DCMAKE_BUILD_TYPE=RelWithDebInfo -DCMAKE_INSTALL_PREFIX="$INSTALL_PREFIX"
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
