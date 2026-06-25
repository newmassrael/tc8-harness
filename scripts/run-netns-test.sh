#!/bin/sh
# Run a test binary inside an unprivileged user + network namespace so it holds
# CAP_NET_ADMIN over a private network stack WITHOUT sudo. Used by the
# posix_neighbor_privileged CTest to exercise the netlink neighbor / ARP-cache
# writes (addStaticNeighbor / removeNeighbor / setNeighborReachableMs) that would
# otherwise only run under root on the self-hosted netns runner.
#
# Where unprivileged user namespaces are unavailable (a locked-down host), the
# test cannot be set up rather than having failed: exit 77 so CTest records a SKIP
# (SKIP_RETURN_CODE), keeping the gate honest instead of red.
set -eu

if ! unshare --user --map-root-user --net true 2>/dev/null; then
    echo "unprivileged user namespaces unavailable; skipping privileged netns test"
    exit 77
fi

exec unshare --user --map-root-user --net "$@"
