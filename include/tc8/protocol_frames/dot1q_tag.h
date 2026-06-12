#pragma once

#include <cstdint>

namespace tc8 {

// IEEE 802.1Q VLAN tag (single customer / C-TAG). The 4-byte tag sits
// between the Ethernet source MAC and the EtherType/Length field:
//
//   | dst MAC (6) | src MAC (6) | TPID (2) | TCI (2) | EtherType (2) | ...
//                                ^^^^^^^^^^^^^^^^^^^^^
//   TPID = 0x8100 (C-TAG). TCI = PCP(3) | DEI(1) | VID(12), big-endian.
//
// Single source of truth for the 802.1Q wire contract: BOTH the decode
// path (`tc8::dissect::PacketPipeline`, via libtins `Dot1Q`) and the
// encode path (`tc8::stimulus::withDot1QTag`) reference the constants
// below, and the round-trip unit test pins encode == decode so the two
// sides cannot drift.
//
// Embedded as a `vlan` member on every L2-visible frame variant (ARP,
// IPv4, ICMPv4, UDP, DHCPv4, TCP). Untagged captures leave `present`
// false and every other field zero. The reassembled application-layer
// `SomeIpFrame` carries no tag — VLAN is an L2 property observable on
// the carrying UDP/TCP frame, not on the stream-reassembled payload.
struct Dot1QTag {
    bool          present = false;  // frame carried an 802.1Q tag
    std::uint16_t tpid    = 0;      // 0x8100 when present
    std::uint8_t  pcp     = 0;      // Priority Code Point, 0..7
    bool          dei     = false;  // Drop Eligible Indicator (legacy CFI)
    std::uint16_t vid     = 0;      // VLAN Identifier, 0..4095
};

// Wire-layout constants for the Tag Control Information halfword. The
// customer VLAN TPID is 0x8100 per IEEE 802.1Q-2018 clause 9.5; the TCI
// packs PCP in bits 15..13, DEI in bit 12, and VID in bits 11..0
// (big-endian on the wire).
inline constexpr std::uint16_t kDot1QTpid     = 0x8100;
inline constexpr unsigned      kDot1QPcpShift = 13;
inline constexpr unsigned      kDot1QDeiShift = 12;
inline constexpr std::uint16_t kDot1QVidMask  = 0x0FFF;

}  // namespace tc8
