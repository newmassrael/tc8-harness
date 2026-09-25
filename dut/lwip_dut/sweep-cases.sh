#!/usr/bin/env bash
# Emits the lwIP-fixture regression case list, one case ID per line —
# the single source of the sweep selection, consumed verbatim by
# dut/lwip_dut/README.md ("Running the sweep") and
# .github/workflows/lwip-sweep.yml. Selection = every case the fixture
# is ASKED to run: the per-platform overrides ledger drops
# expected:false (UT opcode / SOME/IP responder gaps) and
# platform_known_fail (verified lwIP stack deviations).
#
# "Asked", not "can pass", and the difference is one row. A case whose
# premise is a DECLARED CAPABILITY stays on this list and is declined at
# RUN time by the gate (UDP_USER_INTERFACE_07 needs a second DUT address;
# the fixture runs one netif, so it reports skip:requires_capability_*).
# Keeping it here is deliberate: a drop is frozen bookkeeping that a
# fixture gaining the capability would not undo, while the gate re-asks
# every run and starts exercising the case the day the premise holds.
# Listing it in BOTH places would be the duplicate that drifts.
#
# ⚠ The split between "dropped here" and "declined at run time" is
# HISTORICAL, not principled: several expected:false reasons above are
# themselves missing UT opcodes, which is exactly what the 0x16
# DUT-derived capability axis reports. They predate the gate and have no
# capability declaration yet (docs/tech-debt.md TD-25).
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
