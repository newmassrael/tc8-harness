#pragma once

#include <array>
#include <cstdint>

namespace tc8 {

// RFC 826 ARP packet. Fields named after the RFC header layout so that
// TC8 §4.2 pass/fail criteria (e.g. "ARP Target Hardware Address =
// ff:ff:ff:ff:ff:ff", "ARP request reception — Protocol Type correct")
// map one-to-one into transition guards.
struct ArpFrame {
    std::uint16_t hw_type        = 0;  // §4.2: Hardware Type (1 = Ethernet)
    std::uint16_t proto_type     = 0;  // §4.2: Protocol Type (0x0800 = IPv4)
    std::uint8_t  hw_addr_len    = 0;  // §4.2: Hardware Address Length (6)
    std::uint8_t  proto_addr_len = 0;  // §4.2: Protocol Address Length (4)
    std::uint16_t opcode         = 0;  // 1 = request, 2 = reply
    std::array<std::uint8_t, 6> sender_hw{};
    // IPv4 in network byte order, matching what `inet_pton(AF_INET, ...)` writes
    // and what `static_cast<uint32_t>(Tins::IPv4Address)` returns. Comparison
    // against `--expect arp.tester_ip=172.16.0.1` works as long as the parser
    // also produces network byte order — see `parseIpv4Dotted` in expect_parser.
    std::uint32_t sender_proto_ip = 0;
    std::array<std::uint8_t, 6> target_hw{};
    std::uint32_t target_proto_ip = 0;
    // Encapsulating Ethernet header. Distinct from `sender_hw` / `target_hw`
    // for §4.2.4.2 ARP_43 (verifies the Reply's Ethernet *Source* matches DUT
    // MAC) and ARP_19 (Request whose Ethernet destination is broadcast even
    // though target_hw is unicast). For RFC-conformant ARP these typically
    // mirror sender_hw / kEthBroadcast; capturing both lets SCXML guards
    // distinguish frame-level vs. payload-level identity.
    std::array<std::uint8_t, 6> eth_src{};
    std::array<std::uint8_t, 6> eth_dst{};

    // Wall-clock arrival timestamp in microseconds since the Unix
    // epoch — see `TcpFrame::observed_ts_us` for the live/offline
    // precision contract. Mirrored into `ArpCaptured.observed_ts_us`
    // by `fillArpCapturedFromFrame` so future ARP-timing cases (e.g.
    // §4.2.4.x ANNOUNCE_REPS gap timing) can express inter-frame
    // delta guards via `frame_delta_us()`.
    std::int64_t observed_ts_us = 0;
};

}  // namespace tc8
