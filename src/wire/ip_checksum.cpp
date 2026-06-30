#include "wire/ip_checksum.h"

namespace tc8::wire {

std::uint16_t inetChecksum(const std::uint8_t* data, std::size_t len) {
    std::uint32_t sum = 0;
    std::size_t   i   = 0;
    for (; i + 1 < len; i += 2) {
        sum += static_cast<std::uint32_t>(
            (static_cast<std::uint16_t>(data[i]) << 8) | data[i + 1]);
    }
    if (i < len) {
        sum += static_cast<std::uint32_t>(data[i]) << 8;
    }
    while ((sum >> 16) != 0U) {
        sum = (sum & 0xFFFFU) + (sum >> 16);
    }
    return static_cast<std::uint16_t>(~sum & 0xFFFFU);
}

std::uint16_t udpChecksum(std::uint32_t       src_be,
                          std::uint32_t       dst_be,
                          const std::uint8_t* udp,
                          std::size_t         udp_len) {
    std::uint32_t sum = 0;
    auto add16 = [&](std::uint16_t v) { sum += v; };

    const auto* src_bytes = reinterpret_cast<const std::uint8_t*>(&src_be);
    const auto* dst_bytes = reinterpret_cast<const std::uint8_t*>(&dst_be);
    add16(static_cast<std::uint16_t>((src_bytes[0] << 8) | src_bytes[1]));
    add16(static_cast<std::uint16_t>((src_bytes[2] << 8) | src_bytes[3]));
    add16(static_cast<std::uint16_t>((dst_bytes[0] << 8) | dst_bytes[1]));
    add16(static_cast<std::uint16_t>((dst_bytes[2] << 8) | dst_bytes[3]));
    add16(static_cast<std::uint16_t>(0x0011U));  // proto = UDP
    add16(static_cast<std::uint16_t>(udp_len));

    for (std::size_t i = 0; i + 1 < udp_len; i += 2) {
        add16(static_cast<std::uint16_t>(
            (static_cast<std::uint16_t>(udp[i]) << 8) | udp[i + 1]));
    }
    if ((udp_len & 1U) != 0U) {
        add16(static_cast<std::uint16_t>(
            static_cast<std::uint16_t>(udp[udp_len - 1]) << 8));
    }
    while ((sum >> 16) != 0U) {
        sum = (sum & 0xFFFFU) + (sum >> 16);
    }
    auto out = static_cast<std::uint16_t>(~sum & 0xFFFFU);
    if (out == 0U) out = 0xFFFFU;
    return out;
}

std::uint16_t tcpChecksum(std::uint32_t       src_be,
                          std::uint32_t       dst_be,
                          const std::uint8_t* tcp,
                          std::size_t         tcp_len) {
    std::uint32_t sum = 0;
    auto add16 = [&](std::uint16_t v) { sum += v; };

    const auto* src_bytes = reinterpret_cast<const std::uint8_t*>(&src_be);
    const auto* dst_bytes = reinterpret_cast<const std::uint8_t*>(&dst_be);
    add16(static_cast<std::uint16_t>((src_bytes[0] << 8) | src_bytes[1]));
    add16(static_cast<std::uint16_t>((src_bytes[2] << 8) | src_bytes[3]));
    add16(static_cast<std::uint16_t>((dst_bytes[0] << 8) | dst_bytes[1]));
    add16(static_cast<std::uint16_t>((dst_bytes[2] << 8) | dst_bytes[3]));
    add16(static_cast<std::uint16_t>(0x0006U));  // proto = TCP
    add16(static_cast<std::uint16_t>(tcp_len));

    for (std::size_t i = 0; i + 1 < tcp_len; i += 2) {
        add16(static_cast<std::uint16_t>(
            (static_cast<std::uint16_t>(tcp[i]) << 8) | tcp[i + 1]));
    }
    if ((tcp_len & 1U) != 0U) {
        add16(static_cast<std::uint16_t>(
            static_cast<std::uint16_t>(tcp[tcp_len - 1]) << 8));
    }
    while ((sum >> 16) != 0U) {
        sum = (sum & 0xFFFFU) + (sum >> 16);
    }
    // No RFC 768 0x0000→0xFFFF rewrite: TCP transmits a zero checksum as zero.
    return static_cast<std::uint16_t>(~sum & 0xFFFFU);
}

bool inetChecksumValid(const std::uint8_t* data, std::size_t len) {
    // Summed WITH the checksum field in place, a correct on-wire checksum makes
    // the fold all-ones, so inetChecksum's complement is 0.
    return inetChecksum(data, len) == 0U;
}

bool tcpChecksumValid(std::uint32_t src_be, std::uint32_t dst_be,
                      const std::uint8_t* tcp, std::size_t tcp_len) {
    return tcpChecksum(src_be, dst_be, tcp, tcp_len) == 0U;
}

bool udpChecksumValid(std::uint32_t src_be, std::uint32_t dst_be,
                      const std::uint8_t* udp_zeroed, std::size_t udp_len,
                      std::uint16_t on_wire_checksum) {
    const std::uint16_t computed = udpChecksum(src_be, dst_be, udp_zeroed, udp_len);
    if (computed == on_wire_checksum) return true;
    // RFC 768 0x0000/0xFFFF sentinel equivalence: both fold to one's-complement
    // zero, so accept either form.
    return (computed == 0x0000U && on_wire_checksum == 0xFFFFU) ||
           (computed == 0xFFFFU && on_wire_checksum == 0x0000U);
}

}  // namespace tc8::wire
