#!/usr/bin/env bash
# Observable LIVE check of the AUTOSAR Testability IPv6 STATIC_ADDRESS / STATIC_ROUTE
# service primitives (PRS_TPSP §6.10, GID 0x06): assigns a FRESH IPv6 address to the
# DUT's SECONDARY interface over the (IPv4) PRIMARY control channel, then observes that
# the address landed on the interface + is ping6-reachable and that the route is in the
# DUT's table. Both effects are observed HERE, not by the probe: the testability control
# transport is IPv4 (the UTM binds INADDR_ANY = IPv4), so the probe cannot self-observe
# an IPv6 address the way the IPv4 check does. This exercises the E_OK path the hermetic
# unit tests deliberately skip (the privileged write would mutate the build host).
#
# The shared scaffold (Topology-2 netns + standalone tc8-utm + readiness wait) lives in
# lib-sp-check.sh; this script adds the IPv6 addressing + the IPv6-STATIC probe + the
# observations. Must run as root (netns plumbing + STATIC writes need CAP_NET_ADMIN).
set -euo pipefail
# shellcheck source=dut/env/lib-sp-check.sh
source "$(dirname "$(readlink -f "$0")")/lib-sp-check.sh"

sp_check_setup ip6st

# IPv6 addressing for the secondary veth pair (the lib provisions IPv4 only). wire.def
# carries no IPv6 axis (it is IPv4-only by design, and these addresses have no consumer
# beyond this check), so — unlike the IPv4 check, which derives its addresses from the
# wire SSOT — these are check-local. They still single-source within the script: the
# tester (.1, doubling as the route gateway) and the DUT's fresh address (.50, the SP
# assigns it below) both derive from one $V6_NET /64. That ULA net deliberately echoes
# the IPv4 secondary subnet 172.17.0.0/24 as a mnemonic but is independent of it. The
# fresh address shares the /64 so ping6 reaches it; DAD is disabled so it is immediately
# usable rather than tentative for ~1 s. The route target is the RFC 3849 documentation
# prefix, intentionally unroutable.
V6_NET="fd00:17::"
PREFIX=64
TESTER_IP6="${V6_NET}1"
NEW_ADDR6="${V6_NET}50"
ROUTE_SUBNET6="2001:db8:dead::"

for spec in "$DUT_NS:$VETH_D2" "$TESTER_NS:$VETH_T2"; do
    ns="${spec%%:*}"; ifc="${spec##*:}"
    ip netns exec "$ns" sysctl -q -w "net.ipv6.conf.$ifc.disable_ipv6=0"
    ip netns exec "$ns" sysctl -q -w "net.ipv6.conf.$ifc.accept_dad=0"
    ip netns exec "$ns" sysctl -q -w "net.ipv6.conf.$ifc.dad_transmits=0"
done
ip netns exec "$TESTER_NS" ip -6 addr add "$TESTER_IP6/$PREFIX" dev "$VETH_T2"

# Precondition: the fresh address is not yet reachable, so a successful ping6 AFTER the
# SP is unambiguous evidence the assignment took effect.
if ip netns exec "$TESTER_NS" ping -6 -c1 -W1 "$NEW_ADDR6" >/dev/null 2>&1; then
    echo "ipv6-static-check: FAIL — $NEW_ADDR6 already reachable before STATIC_ADDRESS" >&2
    exit 1
fi
echo "ipv6-static-check: precondition -> $NEW_ADDR6 not yet assigned"

# The route must likewise be absent before the SP, so its post-SP presence is the SP's
# doing and not a pre-existing route (otherwise the route observation only proves
# "present after", which a stale route would satisfy).
if ip netns exec "$DUT_NS" ip -6 route show "$ROUTE_SUBNET6/$PREFIX" | grep -q .; then
    echo "ipv6-static-check: FAIL — $ROUTE_SUBNET6/$PREFIX already routed before STATIC_ROUTE" >&2
    exit 1
fi
echo "ipv6-static-check: precondition -> $ROUTE_SUBNET6/$PREFIX not yet routed"

# Drive the IPv6 STATIC loop over the (IPv4) primary control channel: assign $NEW_ADDR6
# to the DUT's secondary interface (VETH_D2), then install the $ROUTE_SUBNET6 route via
# the tester. The probe asserts E_OK for both; this script observes the effects.
ip netns exec "$TESTER_NS" "$HARNESS" testability-probe \
    --dut-ip "$TC8_WIRE_DUT_IP" --no-data \
    --ipv6-static --ipv6-static-iface "$VETH_D2" \
    --ipv6-static-addr "$NEW_ADDR6" --ipv6-static-prefix "$PREFIX" \
    --ipv6-static-route-subnet "$ROUTE_SUBNET6" --ipv6-static-route-gw "$TESTER_IP6" \
    --ipv6-static-route-prefix "$PREFIX"

# Observe STATIC_ADDRESS: the address is on the DUT interface and now ping6-reachable.
if ! ip netns exec "$DUT_NS" ip -6 addr show dev "$VETH_D2" | grep -q "$NEW_ADDR6"; then
    echo "ipv6-static-check: FAIL — STATIC_ADDRESS E_OK but $NEW_ADDR6 absent from DUT iface" >&2
    ip netns exec "$DUT_NS" ip -6 addr show dev "$VETH_D2" >&2
    exit 1
fi
reachable=""
for _ in $(seq 10); do
    if ip netns exec "$TESTER_NS" ping -6 -c1 -W1 "$NEW_ADDR6" >/dev/null 2>&1; then
        reachable=1; break
    fi
    sleep 0.2
done
if [[ "$reachable" != 1 ]]; then
    echo "ipv6-static-check: FAIL — STATIC_ADDRESS E_OK but $NEW_ADDR6 not ping6-reachable" >&2
    exit 1
fi
echo "ipv6-static-check: STATIC_ADDRESS effect observed ($NEW_ADDR6 assigned + reachable)"

# Observe STATIC_ROUTE: its effect is in the DUT's table (no third hop to reach) —
# confirm it directly (the probe asserted E_OK). The gateway is matched as a whole word
# (grep -w) so fd00:17::1 cannot spuriously match a fd00:17::1x sibling.
if ip netns exec "$DUT_NS" ip -6 route show "$ROUTE_SUBNET6/$PREFIX" | grep -qwF "$TESTER_IP6"; then
    echo "ipv6-static-check: STATIC_ROUTE effect observed ($ROUTE_SUBNET6/$PREFIX via $TESTER_IP6)"
else
    echo "ipv6-static-check: FAIL — STATIC_ROUTE reported E_OK but the route is absent" >&2
    ip netns exec "$DUT_NS" ip -6 route show >&2
    exit 1
fi

echo "ipv6-static-check: PASS — IPv6 STATIC_ADDRESS + STATIC_ROUTE observed end to end"
