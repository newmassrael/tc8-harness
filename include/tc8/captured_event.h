#pragma once

#include <variant>

#include "tc8/protocol_frames/arp_frame.h"
#include "tc8/protocol_frames/dhcpv4_frame.h"
#include "tc8/protocol_frames/icmpv4_frame.h"
#include "tc8/protocol_frames/ipv4_frame.h"
#include "tc8/protocol_frames/someip_frame.h"
#include "tc8/protocol_frames/tcp_frame.h"
#include "tc8/protocol_frames/udp_frame.h"

namespace tc8 {

// Single surface the capture pipeline uses to hand decoded packets to
// every registered test runner. Variant alternatives are aligned with
// `tc8::BpfGroup` and with TC8 v3.0 protocol-scope chapters (§4.2–§5.1)
// — adding a protocol here means adding a matching BpfGroup bucket and a
// pipeline decoder.
//
// A runner whose case only watches one protocol does
// `std::get_if<FooFrame>(&ev)` and returns early when it sees anything
// else. Cross-protocol cases (e.g. §4.2 ARP_03 observes both ARP and UDP
// to verify "no ARP request after cache hit") handle multiple
// alternatives in a single `TestCaseTraits<SM>::dispatch`.
using CapturedEvent = std::variant<
    ArpFrame,
    Icmpv4Frame,
    Ipv4Frame,
    UdpFrame,
    Dhcpv4Frame,
    TcpFrame,
    SomeIpFrame>;

}  // namespace tc8
