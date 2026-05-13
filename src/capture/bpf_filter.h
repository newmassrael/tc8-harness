#pragma once

#include <cstdint>
#include <string>

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

// Dispatch: BpfGroup enum → per-group expression above.
std::string expressionFor(::tc8::BpfGroup group);

}  // namespace tc8::capture::bpf
