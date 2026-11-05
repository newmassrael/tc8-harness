#pragma once

#include <array>
#include <cstddef>
#include <cstdint>
#include <cstring>
#include <optional>

#include "tc8/wire/wire_read.h"

// An Ethernet/IPv4 ARP packet (RFC 826) read from an Ethernet payload.
//
// RFC 826 gives the address lengths as fields (ar$hln, ar$pln), and the harness's
// ArpFrame is the Ethernet/IPv4 form: 6-byte hardware and 4-byte protocol addresses in
// the 28-byte layout. The addresses are read at that layout's offsets and the two length
// fields are REPORTED, not used to move them. A conformance case grades the length fields
// themselves (a DUT must send 6 and 4); a DUT whose only fault is a wrong length field
// sends the 28-byte layout with that one byte changed, and reading at the lengths the
// packet states would leave nothing readable, hiding exactly the fault the case grades.
namespace tc8::wire {

inline constexpr std::size_t kArpEthernetIpv4Len = 28;

struct ArpPacket {
    std::uint16_t hw_type = 0;
    std::uint16_t proto_type = 0;
    std::uint8_t hw_addr_len = 0;     // as the packet states it
    std::uint8_t proto_addr_len = 0;  // as the packet states it
    std::uint16_t opcode = 0;
    std::array<std::uint8_t, 6> sender_hw{};
    std::uint32_t sender_proto_be = 0;  // network byte order, as captured
    std::array<std::uint8_t, 6> target_hw{};
    std::uint32_t target_proto_be = 0;
};

// Empty when fewer than the 28 bytes of the Ethernet/IPv4 layout arrived.
inline std::optional<ArpPacket> decodeArp(const std::uint8_t *p, std::size_t n) {
    if (p == nullptr || n < kArpEthernetIpv4Len) {
        return std::nullopt;
    }
    ArpPacket a;
    a.hw_type = static_cast<std::uint16_t>(readBe(p, 2));
    a.proto_type = static_cast<std::uint16_t>(readBe(p + 2, 2));
    a.hw_addr_len = p[4];
    a.proto_addr_len = p[5];
    a.opcode = static_cast<std::uint16_t>(readBe(p + 6, 2));
    std::memcpy(a.sender_hw.data(), p + 8, 6);
    std::memcpy(&a.sender_proto_be, p + 14, 4);
    std::memcpy(a.target_hw.data(), p + 18, 6);
    std::memcpy(&a.target_proto_be, p + 24, 4);
    return a;
}

}  // namespace tc8::wire
