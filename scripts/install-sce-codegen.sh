#!/usr/bin/env bash
# Build sce-codegen at the SCE revision pinned in third_party/sce/VERSION and
# install it as <prefix>/bin/sce-codegen.
#
# The generator is not built from this tree: third_party/sce carries the embed
# snapshot and SCEFindCodegen.cmake, which FINDS a generator on PATH, and the
# configure-time pin check (cmake/tc8_sce_pin.cmake) refuses one built from any
# other revision. So every machine that builds the harness needs this binary at
# exactly the pinned revision, and three places make one:
#   - the "Build & install sce-codegen" step of the `build` job (prefix ~/.local),
#   - the sce-codegen layer of docker/Dockerfile (prefix /usr/local),
#   - bx's tool store on a build machine (`[tools.sce-codegen]` in bx.toml).
# They call this script rather than each carrying the steps, so a change to how
# the generator is built reaches all three or none.
#
# `git clone && git checkout <rev>` rather than a shallow fetch of the revision:
# the pin is an abbreviated sha, which a fetch cannot name, and
# scripts/check-sce-pin-reachable.sh judges the pin by exactly what a clone of
# the default branch can check out.
#
# Usage: scripts/install-sce-codegen.sh <prefix>
#   SCE_REMOTE_URL      upstream to build from (default: the GitHub origin)
set -euo pipefail

if [[ $# -ne 1 || -z "$1" ]]; then
    echo "usage: $0 <prefix>" >&2
    exit 2
fi
prefix="$1"

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
remote="${SCE_REMOTE_URL:-https://github.com/newmassrael/scxml-core-engine.git}"
rev="$(tr -d '[:space:]' < "${repo_root}/third_party/sce/VERSION")"
if [[ -z "${rev}" ]]; then
    echo "[sce-codegen] FAIL: no revision to build (third_party/sce/VERSION is empty)" >&2
    exit 1
fi

work="$(mktemp -d)"
trap 'rm -rf "${work}"' EXIT

echo "[sce-codegen] building ${rev} from ${remote}"
git clone --quiet "${remote}" "${work}/sce-src"
git -C "${work}/sce-src" checkout --quiet "${rev}"
cargo build --release \
    --manifest-path "${work}/sce-src/sce-build/Cargo.toml" \
    --bin sce-codegen --features cli
mkdir -p "${prefix}/bin"
install "${work}/sce-src/target/release/sce-codegen" "${prefix}/bin/"
echo "[sce-codegen] installed $("${prefix}/bin/sce-codegen" --version) at ${prefix}/bin/sce-codegen"
