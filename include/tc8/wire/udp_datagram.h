#pragma once

#include <cstddef>
#include <cstdint>
#include <optional>

#include "tc8/wire/wire_read.h"

// A UDP datagram (RFC 768) read from an IPv4 payload. The Length field is reported as the
// datagram carried it and is not used to cut the payload: the payload is everything the
// IP layer delivered after the 8-byte header. A datagram whose Length disagrees with what
// arrived is a case's to judge (a DUT must discard one whose Length overruns the IP
// payload), and it can only judge it if the disagreement reaches it.
namespace tc8::wire {

inline constexpr std::size_t kUdpHeaderLen = 8;

struct UdpDatagram {
    std::uint16_t src_port = 0;
    std::uint16_t dst_port = 0;
    std::uint16_t length = 0;    // the header's Length field
    std::uint16_t checksum = 0;
    const std::uint8_t *payload = nullptr;  // null when the datagram carries no data
    std::size_t payload_len = 0;
};

// Empty when fewer than the 8 header bytes arrived.
inline std::optional<UdpDatagram> decodeUdp(const std::uint8_t *p, std::size_t n) {
    if (p == nullptr || n < kUdpHeaderLen) {
        return std::nullopt;
    }
    UdpDatagram d;
    d.src_port = static_cast<std::uint16_t>(readBe(p, 2));
    d.dst_port = static_cast<std::uint16_t>(readBe(p + 2, 2));
    d.length = static_cast<std::uint16_t>(readBe(p + 4, 2));
    d.checksum = static_cast<std::uint16_t>(readBe(p + 6, 2));
    if (n > kUdpHeaderLen) {
        d.payload = p + kUdpHeaderLen;
        d.payload_len = n - kUdpHeaderLen;
    }
    return d;
}

}  // namespace tc8::wire
