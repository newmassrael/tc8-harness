#!/usr/bin/env bash
# Observable LIVE check of the AUTOSAR Testability ETH INTERFACE_UP / INTERFACE_DOWN
# service primitive (PRS_TPSP §6.10): commands INTERFACE_DOWN then INTERFACE_UP on
# the DUT's SECONDARY interface over the PRIMARY control channel and observes the
# secondary go unreachable then reachable again. ETH's effect — unlike ICMP's — is
# observable end to end, so this checks the effect, not just the E_OK acknowledgement.
#
# The shared scaffold (Topology-2 netns + standalone tc8-utm + readiness wait) lives
# in lib-sp-check.sh; this script adds only the ETH-specific probe + PASS line. The
# secondary interface keeps the control channel alive while the toggled link drops.
# Must run as root (netns plumbing + administrative link toggle need CAP_NET_ADMIN).
set -euo pipefail
# shellcheck source=dut/env/lib-sp-check.sh
source "$(dirname "$(readlink -f "$0")")/lib-sp-check.sh"

sp_check_setup eth

# Drive the observable ETH loop: toggle the DUT's secondary interface (VETH_D2,
# carrying TC8_WIRE_DUT_IP_2) over the primary control channel and watch the
# secondary's reachability flip down then up.
ip netns exec "$TESTER_NS" "$HARNESS" testability-probe \
    --dut-ip "$TC8_WIRE_DUT_IP" --no-data \
    --eth --eth-iface "$VETH_D2" --eth-observe-ip "$TC8_WIRE_DUT_IP_2"

echo "eth-sp-check: PASS — ETH INTERFACE_DOWN/UP observed end to end"
