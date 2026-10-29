#pragma once

#include <cstdint>

namespace tc8 {

// The fields of the carrying IPv4 header that a case grading an L4 datagram can need,
// defined ONCE for every L4 frame (UdpFrame, TcpFrame, Dhcpv4Frame). A case reads them
// on the one Captured context it already watches, never by pairing it with the
// Ipv4Frame of the same packet: pairing depends on dispatch order, and a field added to
// one L4 type at a time drifts from the others.
//
// Filled by one pipeline helper from the packet's IP header, so the four fields cannot
// be set for one L4 type and forgotten for another. The Captured contexts inherit the
// same type (sce_integration/captured_ipv4_envelope.h), so a frame converts to its
// context with one assignment and the field types cannot drift between the two layers.
//
// Data only, no user-declared constructors: a frame or context deriving from it stays a
// C++17 aggregate.
struct Ipv4Envelope {
    std::uint8_t  ip_tos = 0;                // type-of-service byte (DSCP + ECN)
    std::uint16_t ip_identification = 0;     // RFC 791 Identification
    std::uint8_t  ip_flags = 0;              // 3-bit: Reserved / DF / MF
    std::uint16_t ip_fragment_offset = 0;    // 13-bit, 8-octet units
};

}  // namespace tc8
