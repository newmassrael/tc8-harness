#pragma once

#include <cstddef>
#include <cstdint>
#include <cstring>
#include <optional>

// A read-only view of an Ethernet frame carrying one unfragmented IPv4/UDP datagram:
// its four address fields and where its payload sits. The one parser behind every
// matcher that recognises a DUT-control reply in a frame — the awaited UT request's
// L2 tap, and the stimulus markers the capture pipeline consumes — so the two cannot
// disagree about which frames are datagrams.
//
// Untagged IPv4 only, and unfragmented: the shape of a control reply. On a veth the
// kernel hands an AF_PACKET socket the frame with any 802.1Q tag already moved to its
// metadata, so a tagged network is seen untagged here.

namespace tc8::stimulus {

struct UdpFrameView {
    std::uint32_t src_ip_be = 0;
    std::uint32_t dst_ip_be = 0;
    std::uint16_t src_port = 0;
    std::uint16_t dst_port = 0;
    const std::uint8_t *payload = nullptr;
    std::size_t payload_len = 0;
};

inline std::optional<UdpFrameView> viewUdpFrame(const std::uint8_t *frame, std::size_t n) {
    constexpr std::size_t kEth = 14;
    if (frame == nullptr || n < kEth + 20 || frame[12] != 0x08 || frame[13] != 0x00) {
        return std::nullopt;
    }
    const std::uint8_t *ip = frame + kEth;
    const std::size_t ihl = static_cast<std::size_t>(ip[0] & 0x0FU) * 4U;
    if ((ip[0] >> 4) != 4 || ihl < 20 || ip[9] != 17 || n < kEth + ihl + 8 ||
        ((ip[6] & 0x3FU) | ip[7]) != 0) {  // MF set or a non-zero offset: a fragment
        return std::nullopt;
    }
    const std::uint8_t *udp = ip + ihl;
    const auto be16 = [](const std::uint8_t *p) {
        return static_cast<std::uint16_t>((p[0] << 8) | p[1]);
    };
    const std::size_t udp_len = be16(udp + 4);
    if (udp_len < 8 || kEth + ihl + udp_len > n) {
        return std::nullopt;
    }
    UdpFrameView v;
    std::memcpy(&v.src_ip_be, ip + 12, 4);
    std::memcpy(&v.dst_ip_be, ip + 16, 4);
    v.src_port = be16(udp);
    v.dst_port = be16(udp + 2);
    v.payload = udp + 8;
    v.payload_len = udp_len - 8;
    return v;
}

}  // namespace tc8::stimulus
