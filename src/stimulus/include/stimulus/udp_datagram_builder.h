#pragma once

#include <cstdint>
#include <optional>
#include <vector>

namespace tc8::stimulus {

// Build an 8-byte UDP header (RFC 768) + caller-supplied payload and
// return the bytes ready to drop into an IPv4 frame as `ip_payload` for
// `buildIpv4Frame`. The checksum is computed over the UDP pseudo-header
// (`src_ip`, `dst_ip`, zero, protocol=17, UDP length) + UDP header +
// payload, per RFC 768 / RFC 1122 §4.1.3.4.
//
// `src_ip_be` and `dst_ip_be` are in network byte order — same convention
// as `Ipv4FrameSpec::src_ip` / `dst_ip`. Passing them in matches the IPv4
// frame these bytes will be wrapped into, so checksum validity depends
// only on the caller using the same values at both layers.
//
// RFC 768 allows IPv4 UDP to transmit 0x0000 in the checksum field to
// signal "checksum not computed"; this builder always computes (the
// receiver side then validates via its own pseudo-header reconstruction).
// If the raw-0x0000 case is needed, set `UdpDatagramOverrides::checksum_field`
// to 0x0000 — this writes the literal value AFTER compute, so 0x0000 vs
// "computed-and-happens-to-be-0x0000" is the caller's signalled intent.
std::vector<std::uint8_t> buildUdpDatagram(
    std::uint32_t src_ip_be,
    std::uint32_t dst_ip_be,
    std::uint16_t src_port,
    std::uint16_t dst_port,
    const std::uint8_t *payload,
    std::size_t        payload_len);

// §4.6.5.4 UDP_FIELDS malformed-stimulus knobs. Each override writes a
// raw value into the UDP header AFTER the conformant compute path, so
// the resulting datagram is observably non-conformant in exactly one
// axis — letting per-case SCXML attribute the DUT's drop reason.
//
//   length_field    — overrides the 16-bit Length at bytes [4..5].
//                     UDP_FIELDS_09 passes 0; UDP_FIELDS_10 passes
//                     `actual + 1` to claim more bytes than the IP
//                     payload carries.
//   checksum_field  — overrides the 16-bit Checksum at bytes [6..7].
//                     UDP_FIELDS_15 passes a deliberately-wrong value;
//                     UDP_FIELDS_16 passes 0x0000 to wire the "checksum
//                     not computed" sentinel.
//   truncate_to     — final wire-region size in bytes. If set and < 8,
//                     the returned vector is truncated to that many
//                     bytes, producing a sub-header UDP that Linux
//                     drops at decode (UDP_FIELDS_08). If set and
//                     >= 8, no effect (the caller could just supply
//                     the full payload). If unset, no truncation.
//
// Default-constructed = identical to the no-overrides overload.
struct UdpDatagramOverrides {
    std::optional<std::uint16_t> length_field;
    std::optional<std::uint16_t> checksum_field;
    std::optional<std::size_t>   truncate_to;
};

std::vector<std::uint8_t> buildUdpDatagramWithOverrides(
    std::uint32_t src_ip_be,
    std::uint32_t dst_ip_be,
    std::uint16_t src_port,
    std::uint16_t dst_port,
    const std::uint8_t *payload,
    std::size_t        payload_len,
    const UdpDatagramOverrides &overrides);

}  // namespace tc8::stimulus
