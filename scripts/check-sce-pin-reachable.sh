#!/usr/bin/env bash
# Gate: the SCE revision pinned in third_party/sce/VERSION must be an ancestor of
# upstream's default branch.
#
# Two places turn that revision into a source tree with a plain
# `git clone && git checkout <rev>`: the sce-codegen layer of docker/Dockerfile
# and the "Build & install sce-codegen" step of the `build` job. A clone carries
# the branches and tags the remote still advertises, so a revision that lived
# only on a rewritten or deleted history is not there to check out:
#     error: pathspec '<rev>' did not match any file(s) known to git
# Upstream rewrote its main history once, which orphaned every sha recorded
# before it. Both consumers sit behind a cache (the docker layer cache, and
# actions/cache keyed on the hash of VERSION), so an orphaned pin stays green
# until a cache misses and then fails far from its cause. This gate resolves the
# pin against the remote on every run, with nothing cached in between.
#
# It needs the network, so it lives in CI and not in .githooks/: every hook there
# is offline and runs on every commit, and an orphaned pin appears with no commit
# in this repository at all, so a commit-time check would not see the case that
# happened.
#
# Usage: scripts/check-sce-pin-reachable.sh [rev]
#   rev                 revision to judge (default: contents of third_party/sce/VERSION)
#   SCE_REMOTE_URL      upstream to judge against (default: the GitHub origin)
set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
remote="${SCE_REMOTE_URL:-https://github.com/newmassrael/scxml-core-engine.git}"

if [[ $# -ge 1 ]]; then
    rev="$1"
else
    rev="$(tr -d '[:space:]' < "${repo_root}/third_party/sce/VERSION")"
fi
if [[ -z "${rev}" ]]; then
    echo "[sce-pin] FAIL: no revision to judge (third_party/sce/VERSION is empty)" >&2
    exit 1
fi

work="$(mktemp -d)"
trap 'rm -rf "${work}"' EXIT
graph="${work}/sce-graph.git"

# The default branch only -- what the Dockerfile's bare `git clone` checks out --
# and no trees or blobs: reachability is a property of the commit graph and the
# graph is all this reads.
echo "[sce-pin] fetching the commit graph of ${remote}"
git clone --quiet --bare --single-branch --filter=tree:0 "${remote}" "${graph}"
branch="$(git -C "${graph}" symbolic-ref --short HEAD)"

if ! git -C "${graph}" merge-base --is-ancestor "${rev}" HEAD; then
    echo "[sce-pin] FAIL: ${rev} is not an ancestor of ${branch} at ${remote}" >&2
    echo "[sce-pin] A clone cannot check it out, so every consumer of the pin breaks" >&2
    echo "[sce-pin] the moment its cache misses. Re-vendor third_party/sce from a" >&2
    echo "[sce-pin] commit that is on ${branch} (package_embed.sh in the SCE checkout" >&2
    echo "[sce-pin] writes VERSION and MANIFEST.json together)." >&2
    exit 1
fi
echo "[sce-pin] ok: ${rev} is an ancestor of ${branch}"
