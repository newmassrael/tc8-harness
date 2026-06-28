#pragma once

#include <cstddef>
#include <cstdint>
#include <optional>
#include <string>
#include <string_view>

#include "tc8/bpf_group.h"

// BPF expressions grouped by TC8 v3.0 protocol-scope chapters (§4.2–§5.1).
// Each function returns a tcpdump-syntax filter string ready to feed into
// PcapSource::applyBpf().

namespace tc8::capture::bpf {

// §4.2 — Address Resolution Protocol.
std::string arp();

// §4.3 — Internet Control Message Protocol v4.
std::string icmpv4();

// §4.4 / §4.5 — IPv4 and IPv4 Link Local Addressing (ARP + IPv4).
std::string ipv4();

// §4.6 — User Datagram Protocol.
std::string udp();

// §4.7 — DHCPv4 Client (bootp ports 67 server, 68 client).
std::string dhcpv4();

// §4.8 — Transmission Control Protocol.
std::string tcp();

// §5.1 — Scalable Service-Oriented Middleware over IP.
// Covers the DUT's SD + unicast ports (see tc8/dut_config.h).
std::string someip();

// §4.2 cross-protocol — ARP entry-learning cases (ARP_03..06) that
// simultaneously watch ARP presence/absence and DUT-emitted UDP.
std::string arpAndUdp();

// §4.5.6.1 IPv4_AUTOCONF_INTRO_01 cross-protocol — observe DHCPv4 +
// assert absence of ARP Probes in 169.254/16. Narrower than `arpAndUdp`
// — pinned to BOOTP ports 67/68 so SOME/IP SD multicast does not leak
// into the capture stream.
std::string arpAndDhcpv4();

// §4.7.6.7 CM_05/_06 cross-protocol — observe BOTH the DHCPv4
// lifecycle (port 67/68) AND the post-BOUND DUT-emitted UDP datagram
// to IP-UNUSED-ADDRESS (192.168.99.42).
std::string udpAndDhcpv4();

// Primitive: "udp portrange lo-hi or tcp portrange lo-hi".
std::string portRange(std::uint16_t lo, std::uint16_t hi);

// Primitive: "udp port A [or udp port B ...]" for the `count` UDP ports (host
// order) at `ports`. Empty string when `count == 0`. Bare (not VLAN-wrapped) —
// the caller applies vlanAware() if the capture path needs tag transparency.
// Used to union a case's extra capture ports into the default filter (see
// resolveCaptureFilter); the port VALUES stay with the case (e.g. an OEM
// protocol on non-standard ports), the harness owns the BPF assembly.
std::string udpPorts(const std::uint16_t *ports, std::size_t count);

// Make a filter match its target frames whether or not they carry a
// single IEEE 802.1Q tag: returns `(<expr>) or (vlan and (<expr>))`.
//
// A plain libpcap predicate (`arp`, `ip`, `tcp ...`) reads the L3
// protocol/port fields at fixed Ethernet offsets and so SILENTLY MISSES
// VLAN-tagged frames, where the 4-byte tag shifts every later field. The
// `vlan` keyword inserts that offset adjustment for the predicates that
// follow it, so the second arm matches the tagged copy while the first
// arm keeps matching untagged frames. Single tag only (C-TAG 0x8100);
// QinQ would need a second `vlan`.
//
// Applied once at the `expressionFor` dispatch boundary so every case's
// capture filter is VLAN-transparent without each group function having
// to remember to wrap itself. NOTE: a user-supplied `-f/--bpf` override
// is passed to the kernel verbatim and is NOT wrapped — wrapping an
// already-VLAN-aware override would double the `vlan` keyword.
std::string vlanAware(const std::string &expr);

// Dispatch: BpfGroup enum → per-group expression above, made
// VLAN-transparent via vlanAware().
std::string expressionFor(::tc8::BpfGroup group);

// Resolve the capture filter for one case by precedence:
//   1. `cli_override` — the top-level `-f/--bpf` flag, used verbatim.
//   2. `per_case_expression` — a case's own `kBpfExpression`, verbatim;
//      lets an out-of-tree case ship a filter outside the BpfGroup enum.
//   3. `expressionFor(group)` — the kBpfGroup-derived, VLAN-aware filter,
//      with `extra_udp_ports` (a case's `kExtraCaptureUdpPorts`) OR'd in,
//      VLAN-aware, so a case whose verdict traffic leaves the group's
//      default port range is still captured.
// (1) and (2) are passed to the kernel as-is (the caller owns any
// VLAN-awareness), exactly as a hand-written `-f` is; only (3) is wrapped.
// The extra ports apply to (3) ONLY — a verbatim `-f` / kBpfExpression already
// owns its full scope, so they are never appended to it. This is the single
// place the filter sources are ranked.
std::string resolveCaptureFilter(const std::optional<std::string> &cli_override,
                                 std::string_view per_case_expression,
                                 ::tc8::BpfGroup group,
                                 const std::uint16_t *extra_udp_ports = nullptr,
                                 std::size_t extra_udp_port_count = 0);

}  // namespace tc8::capture::bpf
