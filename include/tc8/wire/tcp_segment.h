#pragma once

#include <cstddef>
#include <cstdint>
#include <optional>

#include "tc8/wire/wire_read.h"

// A TCP segment (RFC 793 §3.1, RFC 9293 §3.1) read from an IPv4 payload. The options are
// walked option by option the way RFC 793 defines them: End of Option List ends the list
// and what follows to the end of the header is padding, No-Operation is one byte, every
// other kind carries a length that counts its kind and length bytes. What the walk finds
// is recorded rather than refused; only a header that cannot be located (fewer than 20
// bytes, a Data Offset below 5 or past the bytes that arrived) makes the segment
// unreadable.
namespace tc8::wire {

inline constexpr std::size_t kTcpFixedHeaderLen = 20;
inline constexpr std::uint8_t kTcpOptEndOfList = 0;
inline constexpr std::uint8_t kTcpOptNoOperation = 1;
inline constexpr std::uint8_t kTcpOptMss = 2;

struct TcpSegment {
    std::uint16_t src_port = 0;
    std::uint16_t dst_port = 0;
    std::uint32_t seq = 0;
    std::uint32_t ack = 0;
    std::uint8_t data_offset = 0;  // in 32-bit words
    // The control bits: the low 8 (CWR ECE URG ACK PSH RST SYN FIN) of the 12 that follow
    // the Data Offset. The upper 4 are reserved (RFC 793) or AccECN's AE (RFC 9768).
    std::uint8_t flags = 0;
    std::uint8_t reserved_bits = 0;  // the 4 bits between Data Offset and CWR
    std::uint16_t window = 0;
    std::uint16_t checksum = 0;
    std::uint16_t urgent_pointer = 0;
    const std::uint8_t *options = nullptr;
    std::size_t options_len = 0;
    // The MSS option's value when the segment carries a well-formed one (kind 2, length 4).
    std::optional<std::uint16_t> mss;
    // An option whose length is below 2 or reaches past the header. The walk stops there.
    bool options_malformed = false;
    const std::uint8_t *payload = nullptr;  // null when the segment carries no data
    std::size_t payload_len = 0;
};

// Empty when no header can be located in the `n` bytes at `p`.
inline std::optional<TcpSegment> decodeTcp(const std::uint8_t *p, std::size_t n) {
    if (p == nullptr || n < kTcpFixedHeaderLen) {
        return std::nullopt;
    }
    TcpSegment s;
    s.src_port = static_cast<std::uint16_t>(readBe(p, 2));
    s.dst_port = static_cast<std::uint16_t>(readBe(p + 2, 2));
    s.seq = readBe(p + 4, 4);
    s.ack = readBe(p + 8, 4);
    s.data_offset = static_cast<std::uint8_t>(p[12] >> 4);
    s.reserved_bits = static_cast<std::uint8_t>(p[12] & 0x0FU);
    s.flags = p[13];
    s.window = static_cast<std::uint16_t>(readBe(p + 14, 2));
    s.checksum = static_cast<std::uint16_t>(readBe(p + 16, 2));
    s.urgent_pointer = static_cast<std::uint16_t>(readBe(p + 18, 2));
    const std::size_t header_len = static_cast<std::size_t>(s.data_offset) * 4U;
    if (header_len < kTcpFixedHeaderLen || header_len > n) {
        return std::nullopt;
    }
    s.options_len = header_len - kTcpFixedHeaderLen;
    if (s.options_len > 0) {
        s.options = p + kTcpFixedHeaderLen;
    }
    std::size_t at = kTcpFixedHeaderLen;
    while (at < header_len) {
        const std::uint8_t kind = p[at];
        if (kind == kTcpOptEndOfList) {
            break;
        }
        if (kind == kTcpOptNoOperation) {
            ++at;
            continue;
        }
        if (at + 1 >= header_len) {
            s.options_malformed = true;
            break;
        }
        const std::size_t len = p[at + 1];
        if (len < 2 || at + len > header_len) {
            s.options_malformed = true;
            break;
        }
        if (kind == kTcpOptMss && len == 4) {
            s.mss = static_cast<std::uint16_t>(readBe(p + at + 2, 2));
        }
        at += len;
    }
    if (n > header_len) {
        s.payload = p + header_len;
        s.payload_len = n - header_len;
    }
    return s;
}

}  // namespace tc8::wire
