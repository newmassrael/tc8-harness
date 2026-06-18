#!/usr/bin/env bash
# Observable LIVE check of the AUTOSAR Testability ETH INTERFACE_UP / INTERFACE_-
# DOWN service primitive (PRS_TPSP §6.10). Stands up a Topology-2 dual-veth netns
# (SECOND_VETH), runs the standalone AUTOSAR UTM (tc8-utm) in the DUT namespace,
# and drives `testability-probe --eth` from the tester namespace: it commands
# INTERFACE_DOWN then INTERFACE_UP on the DUT's SECONDARY interface over the
# PRIMARY control channel and observes the secondary go unreachable then
# reachable again. ETH's effect — unlike ICMP's — is observable, so this checks
# the effect, not just the E_OK acknowledgement.
#
# Single responsibility: a focused integration check, NOT part of the conformance
# case sweep. It reuses setup-netns.sh (the netns SSOT) and tc8-utm (the
# standalone UTM); the second interface is the standard observation vehicle that
# keeps the control channel alive while the toggled link goes down.
#
# Must run as root: the netns plumbing and the administrative link toggle on the
# DUT side both need CAP_NET_ADMIN.
set -euo pipefail

ROOT="$(cd "$(dirname "$(readlink -f "$0")")/../.." && pwd)"
# Wire constants (DUT primary + secondary IPs) — single source of truth in
# tools/wire.def, generated to wire.gen.sh beside setup-netns.sh.
# shellcheck source=/dev/null
source "$ROOT/dut/env/wire.gen.sh"

HARNESS="${HARNESS:-$ROOT/build/tc8-harness}"
UTM="${UTM:-$ROOT/build/dut/utm/tc8-utm}"

# Distinct names so a concurrent or stale conformance smoke (default tc8-tester /
# tc8-dut + veth-tester*) can never collide with this focused check. veth names
# stay within the 15-char interface-name limit.
export TESTER_NS=tc8-eth-tester DUT_NS=tc8-eth-dut
export VETH_T=vte-eth VETH_D=vdu-eth VETH_T2=vte2-eth VETH_D2=vdu2-eth

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

[[ -x "$HARNESS" ]] || { echo "eth-sp-check: harness not built at $HARNESS" >&2; exit 1; }
[[ -x "$UTM" ]]     || { echo "eth-sp-check: tc8-utm not built at $UTM" >&2; exit 1; }

# Provision the dual-interface topology (reuses the netns SSOT; SECOND_VETH adds
# the 172.17.0.0/24 pair the observation rides).
SECOND_VETH=1 "$ROOT/dut/env/setup-netns.sh"

# Standalone UTM in the DUT namespace — binds the testability endpoint on UDP
# :30700 (INADDR_ANY), so it answers on both DUT IPs (primary + secondary).
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
[[ "$ready" == 1 ]] || { echo "eth-sp-check: UTM did not become ready on $TC8_WIRE_DUT_IP" >&2; exit 1; }

# Drive the observable ETH loop: toggle the DUT's secondary interface (VETH_D2,
# carrying TC8_WIRE_DUT_IP_2) over the primary control channel and watch the
# secondary's reachability flip down then up.
ip netns exec "$TESTER_NS" "$HARNESS" testability-probe \
    --dut-ip "$TC8_WIRE_DUT_IP" --no-data \
    --eth --eth-iface "$VETH_D2" --eth-observe-ip "$TC8_WIRE_DUT_IP_2"

echo "eth-sp-check: PASS — ETH INTERFACE_DOWN/UP observed end to end"
