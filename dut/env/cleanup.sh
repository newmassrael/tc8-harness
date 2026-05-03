#!/usr/bin/env bash
# Remove TC8 test network namespaces. Idempotent.
set -euo pipefail

TESTER_NS=${TESTER_NS:-tc8-tester}
DUT_NS=${DUT_NS:-tc8-dut}

[[ $EUID -eq 0 ]] || { echo "cleanup: must run as root (try: sudo $0)" >&2; exit 1; }

ip netns delete "$DUT_NS"    2>/dev/null || true
ip netns delete "$TESTER_NS" 2>/dev/null || true
echo "tc8 netns removed ($TESTER_NS, $DUT_NS)"
