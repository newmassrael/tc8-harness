#pragma once

#include <cstdint>

#include "tc8/protocol_frames/dot1q_tag.h"

namespace tc8 {

// RFC 791 IPv4 header, emitted for §4.4 field-level test cases (Version,
// IHL, TOS, Total Length, Identification, Flags, Fragment Offset, TTL,
// Protocol, Header Checksum, Source/Destination Address) and §4.5
// addressing/forwarding behaviour. Options region is exposed as a raw
// byte range because the TC8 parameters checked against it vary per
// case (Record Route, Timestamp, Strict/Loose Source Routing, etc.).
struct Ipv4Frame {
    std::uint8_t  version         = 0;
    std::uint8_t  ihl             = 0;   // header length in 32-bit words
    std::uint8_t  tos             = 0;
    std::uint16_t total_length    = 0;
    std::uint16_t identification  = 0;
    std::uint8_t  flags           = 0;   // 3-bit: Reserved / DF / MF
    std::uint16_t fragment_offset = 0;   // 13-bit
    std::uint8_t  ttl             = 0;
    std::uint8_t  protocol        = 0;
    std::uint16_t header_checksum = 0;
    std::uint32_t src_addr        = 0;
    std::uint32_t dst_addr        = 0;
    const std::uint8_t* options_data = nullptr;
    std::uint32_t       options_len  = 0;

    // Wall-clock arrival timestamp in microseconds since the Unix
    // epoch — see `TcpFrame::observed_ts_us` for the live/offline
    // precision contract. Mirrored into `Ipv4Captured.observed_ts_us`
    // so §4.4.4.7 REASSEMBLY-style cases (when they land) can express
    // inter-fragment timing assertions via `frame_delta_us()`.
    std::int64_t observed_ts_us = 0;

    // IEEE 802.1Q tag, populated by the dissector when the frame carried
    // one (`present` false on untagged frames). OEM VLAN profiles read
    // this; no in-tree §4.4 or §4.5 case asserts on it.
    Dot1QTag vlan{};
};

}  // namespace tc8
