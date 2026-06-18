#!/usr/bin/env bash
# Observable LIVE check of the AUTOSAR Testability IP STATIC_ADDRESS / STATIC_ROUTE
# service primitives (PRS_TPSP §6.10): assigns a FRESH address to the DUT's
# SECONDARY interface over the PRIMARY control channel and observes that address
# (unreachable before) answer GET_VERSION after, then installs a route and confirms
# it landed in the DUT's table. Both effects are observable — this exercises the
# E_OK path the hermetic unit tests deliberately skip (the privileged write would
# mutate the build host).
#
# The shared scaffold (Topology-2 netns + standalone tc8-utm + readiness wait) lives
# in lib-sp-check.sh; this script adds only the IP-STATIC-specific probe + checks.
# Must run as root (netns plumbing + STATIC_ADDRESS/ROUTE writes need CAP_NET_ADMIN).
set -euo pipefail
# shellcheck source=dut/env/lib-sp-check.sh
source "$(dirname "$(readlink -f "$0")")/lib-sp-check.sh"

sp_check_setup ipst

# A fresh secondary address to assign: host octet .50 in the secondary /24, derived
# from the wire SSOT so it tracks a re-numbering of that domain (keeps the assigned
# address on-link with the gateway below). The route target is RFC 5737 TEST-NET-1,
# intentionally unroutable, via the tester's secondary IP (on-link for the new /24).
NEW_ADDR="${TC8_WIRE_DUT_IP_2%.*}.50"
ROUTE_SUBNET="192.0.2.0"          # RFC 5737 TEST-NET-1 (intentionally unroutable)
ROUTE_GW="$TC8_WIRE_TESTER_IP_2"

# The route must be absent before the SP, so its post-SP presence is the SP's doing and
# not a pre-existing route (the route observation below otherwise only proves "present
# after", which a stale route would satisfy; the address path is already guarded by the
# probe's own reachability precondition).
if ip netns exec "$DUT_NS" ip route show "$ROUTE_SUBNET/24" | grep -q .; then
    echo "ip-static-check: FAIL — $ROUTE_SUBNET/24 already routed before STATIC_ROUTE" >&2
    exit 1
fi

# Drive the observable IP STATIC loop over the primary control channel: assign
# $NEW_ADDR to the DUT's secondary interface (VETH_D2) and confirm it becomes
# reachable, then install the $ROUTE_SUBNET route via $ROUTE_GW.
ip netns exec "$TESTER_NS" "$HARNESS" testability-probe \
    --dut-ip "$TC8_WIRE_DUT_IP" --no-data \
    --ip-static --ip-static-iface "$VETH_D2" --ip-static-addr "$NEW_ADDR" --ip-static-cidr 24 \
    --ip-static-route-subnet "$ROUTE_SUBNET" --ip-static-route-gw "$ROUTE_GW" \
    --ip-static-route-cidr 24

# STATIC_ROUTE's effect is in the DUT's routing table, not observable by reachability
# without a third hop — confirm it directly (the probe asserted E_OK). The gateway is
# matched as a whole word (grep -w) so 172.17.0.1 cannot spuriously match a ...1x sibling.
if ip netns exec "$DUT_NS" ip route show "$ROUTE_SUBNET/24" | grep -qwF "$ROUTE_GW"; then
    echo "ip-static-check: STATIC_ROUTE effect observed ($ROUTE_SUBNET/24 via $ROUTE_GW in DUT table)"
else
    echo "ip-static-check: FAIL — STATIC_ROUTE reported E_OK but the route is absent" >&2
    ip netns exec "$DUT_NS" ip route show >&2
    exit 1
fi

echo "ip-static-check: PASS — IP STATIC_ADDRESS + STATIC_ROUTE observed end to end"
