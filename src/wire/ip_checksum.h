#pragma once

#include <cstddef>
#include <cstdint>

namespace tc8::wire {

// RFC 1071 1's-complement 16-bit checksum over `data`. For an even
// `len` the trailing pad is unused; an odd `len` zero-pads the last
// byte. Callers pre-zero the checksum field in `data` before calling.
//
// Identical algorithm shared by every IPv4-family checksum site in
// the harness (IPv4 header, ICMP body, plus TCP/UDP pseudo-header
// regions assembled inline by the segment builders). Single SSOT
// avoids drift across six former in-tree copies.
std::uint16_t inetChecksum(const std::uint8_t* data, std::size_t len);

// IPv4 + UDP pseudo-header + UDP body checksum (RFC 768). `src_be`
// and `dst_be` are uint32 values whose memory bytes are NBO (the
// codebase's `*_be` convention); `udp` covers the 8-byte UDP header
// followed by the application payload, with the UDP checksum field
// pre-zeroed.
//
// Returns the on-wire checksum value: 0x0000 transmitted as 0xFFFF
// per RFC 768 so 0x0000 unambiguously means "no checksum".
//
// The IP-address halves are summed by reading their NBO bytes via
// `reinterpret_cast<const uint8_t*>`; bit-shifting a host uint32
// happens to be correct only when the address is palindromic (0 or
// all-FF), which is the latent bug the §4.7 S2 server-emulation OFFER
// exercised end-to-end (server IP 172.16.0.10 → bogus checksum →
// kernel UDP silent drop). See reference_dhcpv4_client_ingest.md.
std::uint16_t udpChecksum(std::uint32_t       src_be,
                          std::uint32_t       dst_be,
                          const std::uint8_t* udp,
                          std::size_t         udp_len);

// Big-endian 16/32-bit writers — one-liners callers reach for when
// laying out IPv4/UDP/BOOTP headers in a raw byte buffer. Inline so
// the compiler can fold them at the call site.
inline void writeBe16(std::uint8_t* p, std::uint16_t v) {
    p[0] = static_cast<std::uint8_t>((v >> 8) & 0xFFU);
    p[1] = static_cast<std::uint8_t>(v & 0xFFU);
}

inline void writeBe32(std::uint8_t* p, std::uint32_t v) {
    p[0] = static_cast<std::uint8_t>((v >> 24) & 0xFFU);
    p[1] = static_cast<std::uint8_t>((v >> 16) & 0xFFU);
    p[2] = static_cast<std::uint8_t>((v >>  8) & 0xFFU);
    p[3] = static_cast<std::uint8_t>(v & 0xFFU);
}

// IPv4 CIDR prefix length -> netmask in HOST byte order (0 => 0.0.0.0,
// 32 => 255.255.255.255). Each network backend applies its own
// htonl / lwip_htonl for the wire/socket form, so the bit-math AND the
// count-equals-width shift-UB guard live here once rather than once per
// backend. Precondition: cidr <= 32 (callers reject a wider prefix as
// E_INV before reaching here); a wider value underflows `32 - cidr`.
inline std::uint32_t cidrToMaskHost(std::uint8_t cidr) {
    return cidr == 0 ? 0U : (0xFFFFFFFFU << (32U - cidr));
}

}  // namespace tc8::wire
