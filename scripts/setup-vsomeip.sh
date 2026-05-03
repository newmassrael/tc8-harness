#!/usr/bin/env bash
# Idempotent vsomeip setup: apply tc8-harness patch series, build, install.
# Run after `git submodule update --init --recursive` on a fresh clone, and
# whenever patches/vsomeip/series changes. Requires quilt (apt install quilt).
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

# Apply series. Empty series file is a no-op (no patches yet).
if [[ -s "$PATCHES_DIR/series" ]]; then
    QUILT_PATCHES="$PATCHES_DIR" quilt push -a
fi

# Build + install. Cap parallelism per repo policy.
cmake -B build -DCMAKE_BUILD_TYPE=RelWithDebInfo -DCMAKE_INSTALL_PREFIX="$INSTALL_PREFIX"
cmake --build build -j4
sudo cmake --install build

echo "vsomeip setup complete: $(git -C "$VSOMEIP_DIR" describe --always) -> $INSTALL_PREFIX"
