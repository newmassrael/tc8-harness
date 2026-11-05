#pragma once

#include <array>
#include <cstddef>
#include <cstdint>
#include <cstring>
#include <optional>

#include "tc8/wire/wire_read.h"

// An Ethernet II frame (IEEE 802.3 type field), with at most one IEEE 802.1Q tag, read
// from the bytes a capture delivered. One of the harness's own wire decoders
// (docs/tech-debt.md TD-69): each reads every input its standard allows, records what
// deviates rather than refusing it, and answers "no frame" only when the frame cannot be
// located at all.
namespace tc8::wire {

inline constexpr std::size_t kEthernetHeaderLen = 14;
inline constexpr std::size_t kDot1QTagLen = 4;
inline constexpr std::uint16_t kEtherTypeIpv4 = 0x0800;
inline constexpr std::uint16_t kEtherTypeArp = 0x0806;
inline constexpr std::uint16_t kEtherTypeDot1Q = 0x8100;

struct Dot1QFields {
    std::uint8_t pcp = 0;   // priority code point, 3 bits
    bool dei = false;       // drop eligible indicator
    std::uint16_t vid = 0;  // VLAN identifier, 12 bits
};

struct EthernetFrame {
    std::array<std::uint8_t, 6> dst{};
    std::array<std::uint8_t, 6> src{};
    // The type of what the frame carries, after the 802.1Q tag when there is one.
    std::uint16_t ether_type = 0;
    std::optional<Dot1QFields> dot1q;
    const std::uint8_t *payload = nullptr;
    std::size_t payload_len = 0;
};

// Read the Ethernet II frame of `n` bytes at `p`. Empty when it is shorter than its
// header, or than the 802.1Q tag its type field announces.
inline std::optional<EthernetFrame> decodeEthernet(const std::uint8_t *p, std::size_t n) {
    if (p == nullptr || n < kEthernetHeaderLen) {
        return std::nullopt;
    }
    EthernetFrame f;
    std::memcpy(f.dst.data(), p, 6);
    std::memcpy(f.src.data(), p + 6, 6);
    f.ether_type = static_cast<std::uint16_t>(readBe(p + 12, 2));
    std::size_t off = kEthernetHeaderLen;
    if (f.ether_type == kEtherTypeDot1Q) {
        if (n < kEthernetHeaderLen + kDot1QTagLen) {
            return std::nullopt;
        }
        const auto tci = static_cast<std::uint16_t>(readBe(p + 14, 2));
        Dot1QFields tag;
        tag.pcp = static_cast<std::uint8_t>(tci >> 13);
        tag.dei = ((tci >> 12) & 0x1U) != 0U;
        tag.vid = static_cast<std::uint16_t>(tci & 0x0FFFU);
        f.dot1q = tag;
        f.ether_type = static_cast<std::uint16_t>(readBe(p + 16, 2));
        off += kDot1QTagLen;
    }
    f.payload = p + off;
    f.payload_len = n - off;
    return f;
}

}  // namespace tc8::wire
