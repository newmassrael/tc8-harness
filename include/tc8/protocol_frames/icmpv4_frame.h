#pragma once

#include <cstdint>

#include "tc8/protocol_frames/dot1q_tag.h"

namespace tc8 {

// RFC 792 ICMPv4 packet, carried inside an IPv4 datagram. Covers the
// Type/Code/Checksum header plus the payload region used by §4.3 test
// cases (Echo Request/Reply identifiers, Destination Unreachable codes,
// Time Exceeded, etc.). Encapsulating IPv4 endpoints are included so
// cases can correlate to source/destination without a separate lookup.
struct Icmpv4Frame {
    std::uint32_t src_ip   = 0;
    std::uint32_t dst_ip   = 0;
    std::uint8_t  type     = 0;  // 0 = Echo Reply, 8 = Echo Request, ...
    std::uint8_t  code     = 0;
    std::uint16_t checksum = 0;
    std::uint32_t rest_of_header = 0;  // Echo identifier+seq, next-hop MTU, ...
    const std::uint8_t* payload_data = nullptr;
    std::uint32_t       payload_len  = 0;

    // RFC 792 p17 ICMP Timestamp / Timestamp Reply (type=13/14) body
    // slots, decoded from the wire by the dissector when type matches.
    // Stored in host byte order so SCXML guards compare directly against
    // host-order literals (e.g. `kIcmpTimestampOriginate`). Slots are
    // disjoint from `payload_data` — RFC 792 fixes the Timestamp body
    // size at 20 bytes (8 B header + 12 B timestamps), so the dissector
    // does not surface a separate payload tail for these types. Default
    // 0 preserves the pre-Timestamp Echo-only field shape.
    std::uint32_t originate_timestamp = 0;
    std::uint32_t receive_timestamp   = 0;
    std::uint32_t transmit_timestamp  = 0;

    // Wall-clock arrival timestamp in microseconds since the Unix
    // epoch — see `TcpFrame::observed_ts_us` for the live/offline
    // precision contract. Distinct from RFC 792 `originate_timestamp`
    // / `receive_timestamp` / `transmit_timestamp`, which are body
    // slots in the Timestamp message (type 13/14) carrying ms-since-
    // midnight UT semantics. `observed_ts_us` is the pcap arrival
    // wall clock and applies to every ICMP type uniformly.
    std::int64_t observed_ts_us = 0;

    // IEEE 802.1Q tag, populated by the dissector when the frame carried
    // one (`present` false on untagged frames). OEM VLAN profiles read
    // this; no in-tree §4.3 case asserts on it.
    Dot1QTag vlan{};
};

}  // namespace tc8
