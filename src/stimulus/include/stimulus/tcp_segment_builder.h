#pragma once

#include <cstdint>
#include <optional>
#include <vector>

namespace tc8::stimulus {

// RFC 793 Control Bits (TCP header byte 13, low nibble + bit 6).
// Exposed as literals so §4.8 TCP_BASICS consumers express stimulus
// intent at the named-flag level rather than bit-juggling raw nibbles.
// Byte order matches the on-wire encoding — bit 7 is CWR (RFC 3168
// ECN), bit 0 is FIN.
inline constexpr std::uint8_t kTcpFlagFin = 0x01U;
inline constexpr std::uint8_t kTcpFlagSyn = 0x02U;
inline constexpr std::uint8_t kTcpFlagRst = 0x04U;
inline constexpr std::uint8_t kTcpFlagPsh = 0x08U;
inline constexpr std::uint8_t kTcpFlagAck = 0x10U;
inline constexpr std::uint8_t kTcpFlagUrg = 0x20U;

// Specification of one TCP segment (RFC 793 §3.1). Fields match the
// on-wire header in layout but stay in host-native width so callers
// can write `spec.seq_num = 0x12345678U` without byte-swapping. The
// builder encodes to network byte order during serialisation.
//
// `options` carries raw kind/length/data bytes the caller pre-encodes
// per RFC 793 §3.1 — kind 0 (EOL), kind 1 (NOP), kind 2 (MSS: 4 B
// `02 04 mss_hi mss_lo`), etc. The builder appends NOP padding so the
// options region is 4-byte aligned, recomputes Data Offset = (20 +
// options_len_padded) / 4, and includes options in the checksum.
// Empty default keeps Data Offset = 5 (20 B header, no options).
//
// `payload` is the TCP data segment body — raw bytes the builder drops
// verbatim after the header+options region. Used by §4.8.6.1
// TCP_BASICS_04 iteration 3 ("Data segment" stimulus to a closed
// port).
struct TcpSegmentSpec {
    std::uint16_t src_port       = 0;
    std::uint16_t dst_port       = 0;
    std::uint32_t seq_num        = 0;
    std::uint32_t ack_num        = 0;
    std::uint8_t  flags          = 0;         // kTcpFlag* OR'd together
    std::uint16_t window         = 65535U;    // initial advertised window
    std::uint16_t urgent_pointer = 0;

    std::vector<std::uint8_t> options;
    std::vector<std::uint8_t> payload;

    // Flip one bit of the TCP checksum AFTER the RFC 793 §3.1 pseudo-
    // header compute. §4.8.6.2 TCP_CHECKSUM_02 uses this to assert the
    // DUT's receive-side TCP checksum discard path (RFC 1122 §4.2.2.7
    // p86) — the spec literal is "incorrect checksum"; flipping one
    // bit is the smallest deterministic perturbation that satisfies
    // it. Mirrors `Ipv4FrameSpec::corrupt_ip_checksum` (§4.4.4.2
    // CHECKSUM_02) so a future case that wants both layers corrupted
    // composes naturally.
    bool corrupt_tcp_checksum = false;

    // Force the TCP checksum field to absolute 0x0000 AFTER the
    // pseudo-header compute. Distinct from `corrupt_tcp_checksum`
    // (one-bit XOR perturbation): §4.8.6.X TCP_HEADER_09's spec
    // literal is "Checksum = 0", which is structurally different
    // from "incorrect checksum" — RFC 793 §3.1 mandates a non-zero
    // computed checksum, and Linux's `tcp_checksum_complete` rejects
    // the segment when the field is zero unless the actual sum
    // collapses to 0x0000 (vanishingly rare in practice). Use this
    // flag for HEADER_09's "checksum=0" assertion; use
    // `corrupt_tcp_checksum` for the generic "any wrong sum" shape.
    bool force_zero_tcp_checksum = false;

    // Override the 4-bit reserved nibble between data_offset and the
    // flags byte (RFC 793 §3.1 byte 12 low nibble). Default (nullopt)
    // emits zero per RFC 793. §4.8.6.X TCP_HEADER_06 sets this to
    // 0xF to assert RFC 4413 §4.2.3 "reserved field MUST be ignored
    // on receive" — the DUT's pass criterion is normal in-window
    // ACK regardless of reserved bits. Wire encoding: byte[12] =
    // (data_offset_words << 4) | (reserved & 0x0F).
    std::optional<std::uint8_t> reserved_override;

    // Override the encoded Data Offset (header length in 32-bit
    // words) AFTER the auto-computed value. Default (nullopt)
    // emits (20 + options_padded) / 4. §4.8.6.X TCP_HEADER_07
    // sets this to a value < 5 (e.g., 4) to drive Linux's
    // `tcp_v4_rcv::bad_packet` path; HEADER_08 sets it to a value
    // greater than the actual segment byte count to drive
    // `pskb_may_pull` failure. The actual options/payload bytes
    // stay as encoded — only byte[12] high nibble changes. The
    // checksum is still computed over the actual segment bytes,
    // so HEADER_07/08 segments arrive with a valid checksum but
    // a malformed Data Offset, isolating the spec-asserted reason
    // for drop.
    std::optional<std::uint8_t> data_offset_override;
};

// Build a 20 + options_padded + payload byte TCP segment (RFC 793).
// `src_ip_be` / `dst_ip_be` must match the IPv4 header these bytes
// will be wrapped in — they are not part of the returned buffer, but
// they enter the RFC 793 pseudo-header checksum, so a mismatch at
// either layer fails receive-side validation.
//
// Checksum computation: pseudo-header (src_ip, dst_ip, zero, proto=6,
// tcp_length) + TCP header with checksum placeholder 0x0000 + options
// + payload, one's-complement per RFC 1071. Unlike UDP (RFC 768), the
// TCP checksum is MANDATORY — the 0x0000 sentinel is not reserved for
// "checksum not computed", so the builder never post-overrides a
// zero sum.
std::vector<std::uint8_t> buildTcpSegment(
    std::uint32_t src_ip_be,
    std::uint32_t dst_ip_be,
    const TcpSegmentSpec &spec);

}  // namespace tc8::stimulus
