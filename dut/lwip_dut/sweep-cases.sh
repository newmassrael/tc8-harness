#!/usr/bin/env bash
# Emits the lwIP-fixture regression case list, one case ID per line —
# the single source of the sweep selection, consumed verbatim by
# dut/lwip_dut/README.md ("Running the sweep") and
# .github/workflows/lwip-sweep.yml. Selection = every case the fixture
# can meaningfully pass: the per-platform overrides ledger drops
# expected:false (UT opcode / SOME/IP responder gaps) and
# platform_known_fail (verified lwIP stack deviations).
#
# The category filter exists because the SOME/IP families (SOMEIPSRV_*,
# SOMEIP_ETS_*) test an application-layer stack the lwIP DUT does not
# carry; the ledger cannot express them as per-case entries without
# drowning it in ~230 identical rows. Drop the filter (exclude flags
# alone suffice) on the day a SOME/IP implementation rides this DUT.
set -euo pipefail

HARNESS=${HARNESS:-./build/tc8-harness}
HERE=$(dirname "$(readlink -f "$0")")

"$HARNESS" test --list-cases \
    --inventory-overrides "$HERE/inventory_overrides.json" \
    --exclude-deferred --exclude-platform-known-fail \
  | awk '/^  (ARP|ICMPv4|IPv4|UDP|TCP)_/{print $1}'
