#!/usr/bin/env bash
# Create TC8 test network — two netns (tester/dut) connected by a veth pair.
#
# Idempotent: tears down any prior state before creating.
#
# Envvars (all optional):
#   TESTER_NS, DUT_NS          netns names               (default: tc8-tester / tc8-dut)
#   VETH_T, VETH_D             veth interface names      (default: veth-tester / veth-dut)
#   TESTER_IP, DUT_IP          CIDR addresses            (default: wire.def TESTER_IP/DUT_IP, /24)
#   MCAST_ROUTE                multicast dest for SOME/IP-SD (default: 224.0.0.0/4)
#
# §4.7.6.5 USAGE_01 Topology 2 second veth pair (DIface-1 / TIface-1) —
# enabled when SECOND_VETH=1. Spec demands two distinct broadcast domains
# (N0 / N1) so the second pair is a separate veth, not a macvlan over the
# first. Default off; smoke-test.sh's bring_up_worker opts in only for
# USAGE_01.
#   SECOND_VETH                 0 = single pair (default), 1 = add second pair
#   VETH_T2, VETH_D2            second-pair veth names    (default: veth-tester2 / veth-dut2)
#   TESTER_IP2, DUT_IP2         second-pair CIDR          (default: 172.17.0.1/24 / 172.17.0.2/24)
#
# IEEE 802.1Q VLAN profile (D2 OEM tagged-traffic enablement; default off).
# When VLAN_ID is set, a VLAN subinterface is stacked on each veth and ALL
# L3 configuration (addresses, routes, ARP/NUD sysctls) is homed on the
# subinterface, so every tester<->DUT L3 frame is 802.1Q-tagged. The
# harness and tc8-dut then bind the subinterface name instead of the bare
# veth. TC8 itself has no VLAN cases — this enables OEM profiles layered
# via TC8_EXTRA_CASE_DIRS.
#   VLAN_ID                     unset = no VLAN (default); 1..4094 = tag id
#   TESTER_VLAN_IF, DUT_VLAN_IF subinterface names (default: vlan-tester / vlan-dut;
#                               kept dotless so per-iface sysctl keys stay unambiguous)
set -euo pipefail

# Wire/fixture constants (primary + alias IPs) — single source of truth in
# tools/wire.def, generated to wire.gen.sh beside this script and
# shared with smoke-test.sh + the orchestrator. Sourced so a standalone run gets
# the canonical defaults; the env knobs below still override.
HERE="$(cd "$(dirname "$(readlink -f "$0")")" && pwd)"
source "$HERE/wire.gen.sh"

TESTER_NS=${TESTER_NS:-tc8-tester}
DUT_NS=${DUT_NS:-tc8-dut}
VETH_T=${VETH_T:-veth-tester}
VETH_D=${VETH_D:-veth-dut}
TESTER_IP=${TESTER_IP:-$TC8_WIRE_TESTER_IP/24}
DUT_IP=${DUT_IP:-$TC8_WIRE_DUT_IP/24}
MCAST_ROUTE=${MCAST_ROUTE:-224.0.0.0/4}
SECOND_VETH=${SECOND_VETH:-0}
VETH_T2=${VETH_T2:-veth-tester2}
VETH_D2=${VETH_D2:-veth-dut2}
TESTER_IP2=${TESTER_IP2:-172.17.0.1/24}
DUT_IP2=${DUT_IP2:-172.17.0.2/24}
VLAN_ID=${VLAN_ID:-}
TESTER_VLAN_IF=${TESTER_VLAN_IF:-vlan-tester}
DUT_VLAN_IF=${DUT_VLAN_IF:-vlan-dut}

# Single source of truth for "which interface carries L3". Defaults to the
# bare veth; the opt-in VLAN block below repoints it to the subinterface.
# Every addr/route/sysctl/neigh operation references these, so toggling
# VLAN_ID needs no other edit and leaves the no-VLAN path byte-identical.
TESTER_L3IF="$VETH_T"
DUT_L3IF="$VETH_D"

die() { echo "setup-netns: $*" >&2; exit 1; }

[[ $EUID -eq 0 ]] || die "must run as root (try: sudo $0)"

# Tear down previous state — netns deletion also removes its veth peer.
ip netns delete "$DUT_NS"    2>/dev/null || true
ip netns delete "$TESTER_NS" 2>/dev/null || true
ip link del "$VETH_T"  2>/dev/null || true
ip link del "$VETH_T2" 2>/dev/null || true

ip netns add "$TESTER_NS"
ip netns add "$DUT_NS"

ip link add "$VETH_T" type veth peer name "$VETH_D"
ip link set "$VETH_T" netns "$TESTER_NS"
ip link set "$VETH_D" netns "$DUT_NS"

ip -n "$TESTER_NS" link set lo up
ip -n "$DUT_NS"    link set lo up
ip -n "$TESTER_NS" link set "$VETH_T" up
ip -n "$DUT_NS"    link set "$VETH_D" up

# Opt-in 802.1Q: stack a VLAN subinterface on each veth and repoint L3
# onto it. A netns delete (teardown above) cascades to its subinterfaces,
# so no extra cleanup is needed.
if [[ -n "$VLAN_ID" ]]; then
    ip -n "$TESTER_NS" link add link "$VETH_T" name "$TESTER_VLAN_IF" type vlan id "$VLAN_ID"
    ip -n "$DUT_NS"    link add link "$VETH_D" name "$DUT_VLAN_IF"    type vlan id "$VLAN_ID"
    ip -n "$TESTER_NS" link set "$TESTER_VLAN_IF" up
    ip -n "$DUT_NS"    link set "$DUT_VLAN_IF"    up
    TESTER_L3IF="$TESTER_VLAN_IF"
    DUT_L3IF="$DUT_VLAN_IF"
fi

ip -n "$TESTER_NS" addr add "$TESTER_IP" dev "$TESTER_L3IF"
ip -n "$DUT_NS"    addr add "$DUT_IP"    dev "$DUT_L3IF"

# §4.6.5.5 UDP_USER_INTERFACE_07/_08 caller-specified Source/Destination
# IP axis: spec gates these on `<DUTSupportsDynamicInterface>=TRUE`. With
# a single primary IP per side the axis collapses (only one valid source
# / destination), so the cases vacuously pass on conformant DUT and would
# also pass on a buggy DUT that ignores the caller's choice. Two extra
# /24 addresses on each side make the axis exercisable:
#
#   * DIface-0 alias (DUT) 172.16.0.5 — UI_07 caller asks DUT to emit UDP
#     with src=this alias; SCXML verifies wire src_ip matches.
#   * AIface-0 alias (TESTER) 172.16.0.4 — UI_08 caller asks DUT to emit
#     UDP with dst=this alias; SCXML verifies wire dst_ip matches.
#
# Both addresses single-homed in wire.def (`DUT_ALIAS_IP` / `TESTER_ALIAS_IP`),
# which the generator cross-checks against the `kDutAliasIp4Be` / `kTesterAliasIp4Be`
# compile-time constants in `src/sce_integration/udp_pilot_common.h` (stimulus /
# SCXML cond). Picked outside `HOST2_IP`=172.16.0.3 (already pinned by
# FIELDS_04/_05) so the three secondary literals stay disjoint.
ip -n "$DUT_NS"    addr add "$TC8_WIRE_DUT_ALIAS_IP/24" dev "$DUT_L3IF"
ip -n "$TESTER_NS" addr add "$TC8_WIRE_TESTER_ALIAS_IP/24" dev "$TESTER_L3IF"

# Disable TX checksum offload on both veth ends. Linux's veth driver
# defaults to reporting CHECKSUM_PARTIAL on transmit, leaving the L4
# checksum field carrying only the pseudo-header partial sum (the NIC
# would normally finalise it). On a real wire the destination side
# never sees the partial form because the NIC computes the final
# checksum before the packet leaves. On veth the packet stays
# in-kernel and the destination sees the partial form — pcap on
# either end captures bytes that fail the RFC 793 §3.1 / RFC 768
# pseudo-header validation. §4.8.6.2 TCP_CHECKSUM_03 reads
# captured.tcp_checksum_valid() to assert the DUT-emitted segment
# carries a correct checksum, so the offload must be disabled here
# for the harness to see the value the spec is asserting.
ip netns exec "$TESTER_NS" ethtool -K "$VETH_T" tx off >/dev/null 2>&1 || true
ip netns exec "$DUT_NS"    ethtool -K "$VETH_D" tx off >/dev/null 2>&1 || true

# Enable gratuitous-ARP learning on the DUT interface (required by TC8
# §4.2.4.1 ARP_05/06). Default `arp_accept=0` means Linux silently drops
# gratuitous Responses for IPs not already in the neigh cache — the
# tester's pre-learning injection would be a no-op and those cases would
# fail with a DUT-originated ARP Request. `arp_accept=1` makes the
# kernel honour the announcement and populate <sender_ip, sender_mac>
# from the gratuitous frame, matching the spec's assumed DUT behaviour.
ip netns exec "$DUT_NS" sysctl -wq "net.ipv4.conf.${DUT_L3IF}.arp_accept=1" >/dev/null
ip netns exec "$DUT_NS" sysctl -wq "net.ipv4.conf.all.arp_accept=1"         >/dev/null

# Widen the NUD delay-first-probe window on the DUT (default 5 s) beyond
# the §4.2.4.1 ARP_03/05 listen window (also 5 s). Linux puts a newly-
# learned neigh entry in STALE; first outgoing use transitions STALE →
# DELAY and, if no positive reachability confirmation arrives within
# `delay_first_probe_time` seconds, DELAY → PROBE fires a unicast ARP
# Request. That probe would land inside our absence-check window and
# make ARP_03/05 fail, even though the DUT *did* successfully learn the
# entry from the tester's injected frame — the probe is a Linux-specific
# reachability re-verification, not a cache miss. 30 s comfortably
# covers the 5 s SCXML deadline plus stimulus wall time. The `default.*`
# path doesn't exist in a fresh netns (it templates into per-iface files
# only at interface creation), so only the per-iface setting matters.
ip netns exec "$DUT_NS" sysctl -wq "net.ipv4.neigh.${DUT_L3IF}.delay_first_probe_time=30" >/dev/null

# Suppress tester-side unicast NUD_PROBE. Linux re-verifies a STALE neigh
# entry by sending a unicast ARP Request ("who-has <peer_ip> tell <us>")
# after `delay_first_probe_time` in DELAY state; the probe is what TC8
# §4.2.4.2 absence cases (ARP_21/27/37/42) empirically catch mid-window —
# the DUT's legitimate Reply to the probe matches the absence-fail guard
# `opcode==2 and sender_hw==dut_iface_mac`. pcap evidence (2026-04-21):
# probe fires ~1.4 s after harness start on workers whose tester neigh
# cache still holds a <DUT_IP, DUT_MAC> entry from a prior case.
#
# `ucast_solicit=0` disables those probes on the tester side while leaving
# initial (broadcast) ARP resolution intact. The tester's cache never
# re-validates a stale entry, which is fine because per-case cases don't
# rely on the cache being "fresh" — they only rely on it not spontaneously
# triggering outbound ARP during the listen window. Flushing the tester
# cache between cases is NOT an option: Phase 2 entry-learning (ARP_03..06)
# relies on the DUT keeping the tester's *injected* MAC (kTesterInjectedMac)
# in its cache, and a tester-kernel-initiated ARP during the stimulus
# window would overwrite that per RFC 826 §2.3.
ip netns exec "$TESTER_NS" sysctl -wq "net.ipv4.neigh.${TESTER_L3IF}.ucast_solicit=0" >/dev/null

# Multicast route needed for SOME/IP-SD (224.244.224.245 in vsomeip default).
ip -n "$TESTER_NS" route add "$MCAST_ROUTE" dev "$TESTER_L3IF"
ip -n "$DUT_NS"    route add "$MCAST_ROUTE" dev "$DUT_L3IF"

# §4.7.6.5 USAGE_01 second veth pair. Mirrors the first pair's setup
# (veth + addr + tx-offload off + arp_accept + delay_first_probe_time +
# tester ucast_solicit) so DIface-1 ↔ TIface-1 is a structurally
# identical broadcast domain on a distinct subnet. RFC 2131 §3.6 MUST
# requires the DUT use DHCP through each interface independently, so the
# second pair is a real veth (not a macvlan) — distinct broadcast domains
# matter for the conformant interpretation. Setup-only when SECOND_VETH=1.
if [[ "$SECOND_VETH" == 1 ]]; then
    ip link add "$VETH_T2" type veth peer name "$VETH_D2"
    ip link set "$VETH_T2" netns "$TESTER_NS"
    ip link set "$VETH_D2" netns "$DUT_NS"
    ip -n "$TESTER_NS" link set "$VETH_T2" up
    ip -n "$DUT_NS"    link set "$VETH_D2" up
    ip -n "$TESTER_NS" addr add "$TESTER_IP2" dev "$VETH_T2"
    ip -n "$DUT_NS"    addr add "$DUT_IP2"    dev "$VETH_D2"
    ip netns exec "$TESTER_NS" ethtool -K "$VETH_T2" tx off >/dev/null 2>&1 || true
    ip netns exec "$DUT_NS"    ethtool -K "$VETH_D2" tx off >/dev/null 2>&1 || true
    ip netns exec "$DUT_NS" sysctl -wq "net.ipv4.conf.${VETH_D2}.arp_accept=1" >/dev/null
    ip netns exec "$DUT_NS" sysctl -wq "net.ipv4.neigh.${VETH_D2}.delay_first_probe_time=30" >/dev/null
    ip netns exec "$TESTER_NS" sysctl -wq "net.ipv4.neigh.${VETH_T2}.ucast_solicit=0" >/dev/null
fi

# Reachability sanity check.
ip netns exec "$TESTER_NS" ping -c 1 -W 1 "${DUT_IP%/*}" >/dev/null \
    || die "tester→dut ping failed"
if [[ "$SECOND_VETH" == 1 ]]; then
    ip netns exec "$TESTER_NS" ping -c 1 -W 1 "${DUT_IP2%/*}" >/dev/null \
        || die "tester→dut2 ping failed"
fi

# The reachability ping above exercises Linux's RFC 826 §2.3 "Packet Reception"
# algorithm on the DUT side: the incoming ARP Request from the ping populates
# the DUT's neighbor table with <tester_ip, tester_mac, DELAY>, valid for
# ~30–45 s under default base_reachable_time. TC8 §4.2.4.1 ARP_07..15 ("DUT
# sends ARP Request on cache miss") depend on the DUT having NO tester entry
# when it tries to emit a unicast response, so flush the DUT's table here —
# once, at setup — after the ping has served its sanity purpose. The tester's
# own neighbor cache is intentionally left populated so tester→DUT stimulus
# (UT requests, FindService, SubscribeEventgroup) doesn't eat an ARP
# round-trip before every case.
ip -n "$DUT_NS" neigh flush dev "$DUT_L3IF"

cat <<INFO
tc8 netns ready:
  $TESTER_NS: $TESTER_IP on $TESTER_L3IF
  $DUT_NS:    $DUT_IP on $DUT_L3IF
INFO
if [[ -n "$VLAN_ID" ]]; then
    echo "  802.1Q: VLAN $VLAN_ID ($TESTER_VLAN_IF over $VETH_T / $DUT_VLAN_IF over $VETH_D)"
fi
if [[ "$SECOND_VETH" == 1 ]]; then
    cat <<INFO2
  $TESTER_NS: $TESTER_IP2 on $VETH_T2 (USAGE_01)
  $DUT_NS:    $DUT_IP2 on $VETH_D2 (USAGE_01)
INFO2
fi
cat <<INFO
run harness inside tester ns:
  sudo ip netns exec $TESTER_NS /home/coin/tc8-harness/build/tc8-harness live -i $TESTER_L3IF

teardown:
  sudo $(dirname "$(readlink -f "$0")")/cleanup.sh
INFO
