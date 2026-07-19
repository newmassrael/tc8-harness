#!/usr/bin/env bash
# Run the tc8-orchestrator (or any argv) inside a PRIVATE network + mount namespace
# so its per-worker netns/veths (`tc8-tester-<w>` / `tc8-dut-<w>`, `veth-*-<w>`)
# cannot collide with a concurrent orchestrator instance on the same host — e.g. an
# OEM conformance run driving the vendored copy of this binary, which uses the
# identical fixed names in the shared `/run/netns` + root network namespace.
#
# Why this is needed: single-pc rebuilds a worker's netns before every case, which
# widens the create/delete window ~700x versus a once-per-worker bring-up. That
# window overlapping a co-tenant's same-named netns ops produces transient
# `RTNETLINK File exists` / `Invalid netns value` / `Cannot open namespace` faults
# that abort the run. A private net + mount namespace removes the shared state
# entirely: our netns names and veth devices live in namespaces the co-tenant
# cannot see, and a private tmpfs over `/run/netns` keeps our name files ours alone.
#
# Scope: use this ONLY for netns-owning topologies (single-pc). Topologies that need
# the host or a remote network — external, ssh-remote, lwip-tap — must NOT be
# wrapped, since `--net` would hide the host stack / break the ssh transport.
#
# Requires root (the smoke lanes already invoke this under sudo) and an `unshare`
# that supports `--net --mount`. `--propagation private` keeps the tmpfs mount from
# leaking to the host mount namespace.
set -euo pipefail

# shellcheck disable=SC2016  # the inner `bash -c` expands "$@"/mount, not this shell
exec unshare --net --mount --propagation private -- bash -c '
    set -euo pipefail
    # Shadow /run/netns with a private tmpfs so `ip netns add` name files are ours
    # alone (the veth devices are already isolated by the private net namespace).
    mount -t tmpfs tmpfs /run/netns
    # A fresh net namespace ships lo DOWN; bring it up so anything expecting a
    # working loopback in the run root behaves as on the host.
    ip link set lo up 2>/dev/null || true
    exec "$@"
' -- "$@"
