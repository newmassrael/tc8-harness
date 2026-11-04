#pragma once

#include <cstddef>
#include <cstdint>
#include <cstring>
#include <optional>

#include "tc8/wire/wire_read.h"

// The IPv4 header as RFC 791 §3.1 defines it, read from the wire.
//
// WHY THE HARNESS READS IT ITSELF
// -------------------------------
// The capture path used libtins alone, and libtins refuses an options area in which
// End of Option List is not the last byte. RFC 791 §3.1 defines exactly that shape as
// normal: the End of Option List "need only be used if the end of the options would
// not otherwise coincide with the end of the internet header", and "the internet
// header padding is used to ensure that the internet header ends on a 32-bit
// boundary. The padding is zero." An embedded target answered an Echo Request whose
// options were `EOL` plus three padding bytes with a reply carrying the same options;
// libtins threw on the reply and three cases graded a reply on the wire as "no reply".
// A tester must read every header the RFC allows; whether the DUT should have sent a
// given header is the case's question, not the parser's.
//
// WHAT IT ANSWERS
// ---------------
// The fixed 20 bytes and the extent of the options area, walked option by option, so
// an End of Option List byte inside another option's data is not taken for the end.
// The walk records what it found rather than refusing: where the option list ended,
// whether the padding after an End of Option List was zero, and whether an option ran
// past the area. None of those make the header unreadable; only a header that cannot
// be located at all is (fewer bytes than 20, a version other than 4, an IHL below 5 or
// past the captured bytes).
namespace tc8::wire {

inline constexpr std::size_t kIpv4FixedHeaderLen = 20;

// Option types with no length byte (RFC 791 §3.1, "Case 1: a single octet").
inline constexpr std::uint8_t kIpv4OptEndOfList = 0x00;
inline constexpr std::uint8_t kIpv4OptNoOperation = 0x01;

struct Ipv4Header {
    std::uint8_t version = 0;
    std::uint8_t ihl = 0;  // in 32-bit words
    std::uint8_t tos = 0;
    std::uint16_t total_length = 0;
    std::uint16_t identification = 0;
    std::uint8_t flags = 0;             // the top 3 bits of byte 6
    std::uint16_t fragment_offset = 0;  // in 8-byte units
    std::uint8_t ttl = 0;
    std::uint8_t protocol = 0;
    std::uint16_t header_checksum = 0;
    std::uint32_t src_be = 0;  // network byte order, as captured
    std::uint32_t dst_be = 0;

    // The options area: the IHL*4 - 20 bytes after the fixed header.
    std::size_t options_offset = kIpv4FixedHeaderLen;
    std::size_t options_len = 0;

    // Where the End of Option List stands, relative to the start of the header, when
    // the walk met one; everything after it, to the end of the area, is padding.
    std::optional<std::size_t> end_of_list_at;
    // RFC 791: "The padding is zero." Set when a padding byte after the End of Option
    // List was not. A fact about the sender, recorded, not a reason to refuse.
    bool padding_nonzero = false;
    // An option whose length byte is below 2 or reaches past the options area. The
    // walk stops there; the fixed header is still read.
    bool options_malformed = false;

    std::size_t headerLen() const noexcept { return static_cast<std::size_t>(ihl) * 4U; }
};

// Read the IPv4 header at `p` (`n` bytes available from there). Empty when no header
// can be located: fewer than 20 bytes, a version other than 4, an IHL below 5, or an
// IHL that reaches past the `n` bytes.
inline std::optional<Ipv4Header> decodeIpv4Header(const std::uint8_t *p, std::size_t n) {
    if (p == nullptr || n < kIpv4FixedHeaderLen) {
        return std::nullopt;
    }
    Ipv4Header h;
    h.version = static_cast<std::uint8_t>(p[0] >> 4);
    h.ihl = static_cast<std::uint8_t>(p[0] & 0x0F);
    if (h.version != 4 || h.headerLen() < kIpv4FixedHeaderLen || h.headerLen() > n) {
        return std::nullopt;
    }
    h.tos = p[1];
    h.total_length = static_cast<std::uint16_t>(readBe(p + 2, 2));
    h.identification = static_cast<std::uint16_t>(readBe(p + 4, 2));
    h.flags = static_cast<std::uint8_t>(p[6] >> 5);
    h.fragment_offset = static_cast<std::uint16_t>(readBe(p + 6, 2) & 0x1FFFU);
    h.ttl = p[8];
    h.protocol = p[9];
    h.header_checksum = static_cast<std::uint16_t>(readBe(p + 10, 2));
    // The wire bytes copied as they stand, the harness's `_be` convention (the memory
    // of the value is in network order, whatever the host's).
    std::memcpy(&h.src_be, p + 12, sizeof(h.src_be));
    std::memcpy(&h.dst_be, p + 16, sizeof(h.dst_be));
    h.options_len = h.headerLen() - kIpv4FixedHeaderLen;

    const std::size_t end = h.headerLen();
    std::size_t at = kIpv4FixedHeaderLen;
    while (at < end) {
        const std::uint8_t type = p[at];
        if (type == kIpv4OptEndOfList) {
            h.end_of_list_at = at;
            for (std::size_t pad = at + 1; pad < end; ++pad) {
                if (p[pad] != 0) {
                    h.padding_nonzero = true;
                    break;
                }
            }
            break;
        }
        if (type == kIpv4OptNoOperation) {
            ++at;
            continue;
        }
        // RFC 791 "Case 2": type, length (counting the type and length octets), data.
        if (at + 1 >= end) {
            h.options_malformed = true;
            break;
        }
        const std::size_t len = p[at + 1];
        if (len < 2 || at + len > end) {
            h.options_malformed = true;
            break;
        }
        at += len;
    }
    return h;
}

}  // namespace tc8::wire
