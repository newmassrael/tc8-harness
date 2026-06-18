#!/usr/bin/env bash
# Shared scaffold for the AUTOSAR Testability service-primitive observable checks
# (testability-eth-sp-check.sh, testability-ip-static-check.sh, …). SOURCED by each
# check, never executed directly. A check sources this, calls `sp_check_setup
# <name-suffix>`, then drives its own `testability-probe` arm + assertion and prints
# its own PASS line. Must run as root: the netns plumbing and the privileged SP
# writes both need CAP_NET_ADMIN.
#
# After `sp_check_setup <suffix>` returns, the caller has: ROOT, HARNESS, UTM,
# TESTER_NS, DUT_NS, VETH_T/D/T2/D2, and the wire constants from wire.gen.sh
# (TC8_WIRE_DUT_IP, TC8_WIRE_DUT_IP_2, TC8_WIRE_TESTER_IP_2, …). The Topology-2
# dual-veth netns is up and the standalone tc8-utm is answering on the primary; the
# EXIT-trap teardown is registered.

# ROOT from THIS file's location (dut/env/lib-sp-check.sh -> ../..), robust to how
# the sourcing check was invoked.
ROOT="$(cd "$(dirname "$(readlink -f "${BASH_SOURCE[0]}")")/../.." && pwd)"
# Wire constants (DUT primary + secondary IPs) — single source of truth in
# tools/wire.def, generated to wire.gen.sh beside setup-netns.sh.
# shellcheck source=/dev/null
source "$ROOT/dut/env/wire.gen.sh"

HARNESS="${HARNESS:-$ROOT/build/tc8-harness}"
UTM="${UTM:-$ROOT/build/dut/utm/tc8-utm}"

_SP_UTM_PID=""
_sp_check_cleanup() {
    if [[ -n "$_SP_UTM_PID" ]]; then
        kill "$_SP_UTM_PID" 2>/dev/null || true
    fi
    pkill -f "$UTM" 2>/dev/null || true
    ip netns delete "$DUT_NS"    2>/dev/null || true
    ip netns delete "$TESTER_NS" 2>/dev/null || true
    ip link del "$VETH_T"  2>/dev/null || true
    ip link del "$VETH_T2" 2>/dev/null || true
}

# sp_check_setup <suffix>: provision a Topology-2 dual-veth netns named for <suffix>
# (distinct from the conformance-smoke defaults so a concurrent/stale run can't
# collide), spawn the standalone tc8-utm in the DUT namespace, and block until it
# answers GET_VERSION on the primary control channel. Registers the EXIT-trap
# teardown. Exits non-zero on any precondition failure.
sp_check_setup() {
    local suffix="$1"
    [[ -n "$suffix" ]] || { echo "sp_check_setup: missing name suffix" >&2; exit 1; }

    # Distinct NS/veth names (within the 15-char interface-name limit) so a default
    # conformance smoke (tc8-tester / tc8-dut + veth-tester*) never collides.
    export TESTER_NS="tc8-${suffix}-tester" DUT_NS="tc8-${suffix}-dut"
    export VETH_T="vte-${suffix}" VETH_D="vdu-${suffix}"
    export VETH_T2="vte2-${suffix}" VETH_D2="vdu2-${suffix}"

    trap _sp_check_cleanup EXIT

    [[ -x "$HARNESS" ]] || { echo "sp-check: harness not built at $HARNESS" >&2; exit 1; }
    [[ -x "$UTM" ]]     || { echo "sp-check: tc8-utm not built at $UTM" >&2; exit 1; }

    # Provision the dual-interface topology (reuses the netns SSOT; SECOND_VETH adds
    # the 172.17.0.0/24 pair the observable checks ride / reconfigure).
    SECOND_VETH=1 "$ROOT/dut/env/setup-netns.sh"

    # Standalone UTM in the DUT namespace — binds the testability endpoint on UDP
    # :30700 (INADDR_ANY), so it answers on every DUT IP (primary + secondary).
    ip netns exec "$DUT_NS" "$UTM" &
    _SP_UTM_PID=$!

    # Wait for the UTM to answer GET_VERSION on the PRIMARY control channel.
    local ready=""
    for _ in $(seq 30); do
        if ip netns exec "$TESTER_NS" "$HARNESS" testability-probe \
               --dut-ip "$TC8_WIRE_DUT_IP" --timeout 200 --no-data >/dev/null 2>&1; then
            ready=1
            break
        fi
        sleep 0.1
    done
    [[ "$ready" == 1 ]] || { echo "sp-check: UTM did not become ready on $TC8_WIRE_DUT_IP" >&2; exit 1; }
}
