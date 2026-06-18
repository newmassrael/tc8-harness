#!/usr/bin/env bash
# Observable LIVE check of the AUTOSAR Testability IP STATIC_ADDRESS / STATIC_ROUTE
# service primitives (PRS_TPSP §6.10). Stands up a Topology-2 dual-veth netns
# (SECOND_VETH), runs the standalone AUTOSAR UTM (tc8-utm) in the DUT namespace,
# and drives `testability-probe --ip-static` from the tester namespace over the
# PRIMARY control channel: it commands STATIC_ADDRESS to assign a FRESH address to
# the DUT's SECONDARY interface and observes that address (unreachable before)
# answer GET_VERSION after, then commands STATIC_ROUTE and this script confirms the
# route landed in the DUT's table. Both effects are observable, so this checks the
# effect, not just the E_OK acknowledgement — the E_OK path the hermetic unit tests
# deliberately skip (the privileged write would mutate the build host).
#
# Single responsibility: a focused integration check, NOT part of the conformance
# case sweep. It reuses setup-netns.sh (the netns SSOT) and tc8-utm (the standalone
# UTM); the secondary interface is the standard observation vehicle that keeps the
# control channel alive while the secondary is reconfigured.
#
# Must run as root: the netns plumbing and the STATIC_ADDRESS / STATIC_ROUTE writes
# on the DUT side both need CAP_NET_ADMIN.
set -euo pipefail

ROOT="$(cd "$(dirname "$(readlink -f "$0")")/../.." && pwd)"
# Wire constants (DUT primary + secondary IPs) — single source of truth in
# tools/wire.def, generated to wire.gen.sh beside setup-netns.sh.
# shellcheck source=/dev/null
source "$ROOT/dut/env/wire.gen.sh"

HARNESS="${HARNESS:-$ROOT/build/tc8-harness}"
UTM="${UTM:-$ROOT/build/dut/utm/tc8-utm}"

# A fresh secondary address to assign (unused before the check) and an RFC 5737
# documentation subnet to route — neither collides with the wire constants.
NEW_ADDR="172.17.0.50"
ROUTE_SUBNET="192.0.2.0"
ROUTE_GW="$TC8_WIRE_TESTER_IP_2"  # 172.17.0.1: on-link for the DUT's new /24

# Distinct names so a concurrent or stale conformance smoke (default tc8-tester /
# tc8-dut + veth-tester*) can never collide with this focused check. veth names
# stay within the 15-char interface-name limit.
export TESTER_NS=tc8-ipst-tester DUT_NS=tc8-ipst-dut
export VETH_T=vte-ipst VETH_D=vdu-ipst VETH_T2=vte2-ipst VETH_D2=vdu2-ipst

UTM_PID=""
cleanup() {
    if [[ -n "$UTM_PID" ]]; then
        kill "$UTM_PID" 2>/dev/null || true
    fi
    pkill -f "$UTM" 2>/dev/null || true
    ip netns delete "$DUT_NS"    2>/dev/null || true
    ip netns delete "$TESTER_NS" 2>/dev/null || true
    ip link del "$VETH_T"  2>/dev/null || true
    ip link del "$VETH_T2" 2>/dev/null || true
}
trap cleanup EXIT

[[ -x "$HARNESS" ]] || { echo "ip-static-check: harness not built at $HARNESS" >&2; exit 1; }
[[ -x "$UTM" ]]     || { echo "ip-static-check: tc8-utm not built at $UTM" >&2; exit 1; }

# Provision the dual-interface topology (reuses the netns SSOT; SECOND_VETH adds
# the 172.17.0.0/24 pair the STATIC loop reconfigures + observes).
SECOND_VETH=1 "$ROOT/dut/env/setup-netns.sh"

# Standalone UTM in the DUT namespace — binds the testability endpoint on UDP
# :30700 (INADDR_ANY), so it answers on the primary, the original secondary, and
# the newly-assigned secondary address alike.
ip netns exec "$DUT_NS" "$UTM" &
UTM_PID=$!

# Wait for the UTM to answer GET_VERSION on the PRIMARY control channel.
ready=""
for _ in $(seq 30); do
    if ip netns exec "$TESTER_NS" "$HARNESS" testability-probe \
           --dut-ip "$TC8_WIRE_DUT_IP" --timeout 200 --no-data >/dev/null 2>&1; then
        ready=1
        break
    fi
    sleep 0.1
done
[[ "$ready" == 1 ]] || { echo "ip-static-check: UTM did not become ready on $TC8_WIRE_DUT_IP" >&2; exit 1; }

# Drive the observable IP STATIC loop over the primary control channel: assign
# $NEW_ADDR to the DUT's secondary interface (VETH_D2) and confirm it becomes
# reachable, then install the $ROUTE_SUBNET route via $ROUTE_GW.
ip netns exec "$TESTER_NS" "$HARNESS" testability-probe \
    --dut-ip "$TC8_WIRE_DUT_IP" --no-data \
    --ip-static --ip-static-iface "$VETH_D2" --ip-static-addr "$NEW_ADDR" --ip-static-cidr 24 \
    --ip-static-route-subnet "$ROUTE_SUBNET" --ip-static-route-gw "$ROUTE_GW" \
    --ip-static-route-cidr 24

# STATIC_ROUTE's effect is in the DUT's routing table, not observable by
# reachability without a third hop — confirm it directly (the probe asserted E_OK).
if ip netns exec "$DUT_NS" ip route show "$ROUTE_SUBNET/24" | grep -q "via $ROUTE_GW"; then
    echo "ip-static-check: STATIC_ROUTE effect observed ($ROUTE_SUBNET/24 via $ROUTE_GW in DUT table)"
else
    echo "ip-static-check: FAIL — STATIC_ROUTE reported E_OK but the route is absent" >&2
    ip netns exec "$DUT_NS" ip route show >&2
    exit 1
fi

echo "ip-static-check: PASS — IP STATIC_ADDRESS + STATIC_ROUTE observed end to end"
