#pragma once

#include <array>
#include <cstdint>

namespace tc8 {

// RFC 768 UDP header plus encapsulating IPv4 endpoints and the Ethernet
// addresses of the carrying frame. §4.6 test cases verify field contents
// (Source/Destination Port, Length, Checksum); §4.2 cross-protocol cases
// (ARP_04/06) additionally read `eth_dst` to prove the DUT honoured a
// previously-learned ARP entry when emitting this UDP datagram. The
// payload pointer is non-owning and valid only during the
// ITestRunner::onCaptured() call.
//
// `ip_flags` / `ip_fragment_offset` mirror the carrying IPv4 header's
// fragmentation fields (RFC 791 §3.1). §4.4.4.6 FRAGMENTS_05 asserts
// MF=0 + offset=0 on a DUT-originated UDP datagram, and pushing the
// fields down to UdpFrame lets the SCXML watch one Captured context
// (UdpCaptured) instead of correlating across Ipv4Frame + UdpFrame.
struct UdpFrame {
    std::uint32_t src_ip   = 0;
    std::uint32_t dst_ip   = 0;
    std::uint16_t src_port = 0;
    std::uint16_t dst_port = 0;
    std::uint16_t length   = 0;   // UDP header length field (RFC 768)
    std::uint16_t checksum = 0;
    std::uint8_t  ip_flags = 0;           // 3-bit: Reserved / DF / MF
    std::uint16_t ip_fragment_offset = 0; // 13-bit, 8-octet units
    std::array<std::uint8_t, 6> eth_src{};
    std::array<std::uint8_t, 6> eth_dst{};
    const std::uint8_t* payload_data = nullptr;
    std::uint32_t       payload_len  = 0;

    // Wall-clock arrival timestamp in microseconds since the Unix
    // epoch — see `TcpFrame::observed_ts_us` for the live/offline
    // precision contract. Mirrored into `UdpCaptured.observed_ts_us`
    // so §4.6 SOME/IP-SD Initial Wait Phase / Repetitions Phase
    // timing cases can express inter-frame delta guards via
    // `frame_delta_us()`.
    std::int64_t observed_ts_us = 0;
};

}  // namespace tc8
