#pragma once

#include <cstddef>
#include <cstdint>
#include <optional>

#include "tc8/wire/wire_read.h"

// An ICMPv4 message (RFC 792) read from an IPv4 payload. Every message has the 8-byte
// header (type, code, checksum, and four bytes whose meaning depends on the type: an
// Echo's identifier and sequence number, a Parameter Problem's pointer, an MTU). The
// Timestamp and Timestamp Reply messages carry three 32-bit timestamps after it (RFC
// 792, 20 bytes in all), the Address Mask messages a 32-bit mask (RFC 950, 12 bytes);
// what follows the type's fixed part is the message's payload (an Echo's data, an error
// message's original datagram).
namespace tc8::wire {

inline constexpr std::size_t kIcmpHeaderLen = 8;
inline constexpr std::uint8_t kIcmpTimestamp = 13;
inline constexpr std::uint8_t kIcmpTimestampReply = 14;
inline constexpr std::uint8_t kIcmpAddressMaskRequest = 17;
inline constexpr std::uint8_t kIcmpAddressMaskReply = 18;

struct Icmpv4Message {
    std::uint8_t type = 0;
    std::uint8_t code = 0;
    std::uint16_t checksum = 0;
    std::uint32_t rest_of_header = 0;  // bytes 4..7, big-endian
    // Timestamp / Timestamp Reply only, in host order (milliseconds since midnight UT).
    std::uint32_t originate_timestamp = 0;
    std::uint32_t receive_timestamp = 0;
    std::uint32_t transmit_timestamp = 0;
    const std::uint8_t *payload = nullptr;  // null when the message has none
    std::size_t payload_len = 0;
};

// The length of the fixed part of a message of `type`.
constexpr std::size_t icmpFixedLen(std::uint8_t type) {
    switch (type) {
        case kIcmpTimestamp:
        case kIcmpTimestampReply:
            return kIcmpHeaderLen + 12;
        case kIcmpAddressMaskRequest:
        case kIcmpAddressMaskReply:
            return kIcmpHeaderLen + 4;
        default:
            return kIcmpHeaderLen;
    }
}

// Empty when the message is shorter than its type's fixed part.
inline std::optional<Icmpv4Message> decodeIcmpv4(const std::uint8_t *p, std::size_t n) {
    if (p == nullptr || n < kIcmpHeaderLen) {
        return std::nullopt;
    }
    Icmpv4Message m;
    m.type = p[0];
    m.code = p[1];
    m.checksum = static_cast<std::uint16_t>(readBe(p + 2, 2));
    m.rest_of_header = readBe(p + 4, 4);
    const std::size_t fixed = icmpFixedLen(m.type);
    if (n < fixed) {
        return std::nullopt;
    }
    if (m.type == kIcmpTimestamp || m.type == kIcmpTimestampReply) {
        m.originate_timestamp = readBe(p + 8, 4);
        m.receive_timestamp = readBe(p + 12, 4);
        m.transmit_timestamp = readBe(p + 16, 4);
    }
    if (n > fixed) {
        m.payload = p + fixed;
        m.payload_len = n - fixed;
    }
    return m;
}

}  // namespace tc8::wire
