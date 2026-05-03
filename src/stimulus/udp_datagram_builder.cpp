#include "stimulus/udp_datagram_builder.h"

#include "wire/ip_checksum.h"

#include <cstring>

namespace tc8::stimulus {

namespace {

constexpr std::uint8_t  kIpProtoUdp = 0x11;  // IANA protocol 17

void appendBe16(std::vector<std::uint8_t> &b, std::uint16_t v) {
    b.push_back(static_cast<std::uint8_t>((v >> 8) & 0xFFU));
    b.push_back(static_cast<std::uint8_t>(v & 0xFFU));
}

using ::tc8::wire::inetChecksum;

}  // namespace

std::vector<std::uint8_t> buildUdpDatagramWithOverrides(
        std::uint32_t src_ip_be,
        std::uint32_t dst_ip_be,
        std::uint16_t src_port,
        std::uint16_t dst_port,
        const std::uint8_t *payload,
        std::size_t        payload_len,
        const UdpDatagramOverrides &overrides) {
    const std::uint16_t udp_length =
        static_cast<std::uint16_t>(8U + payload_len);

    // Build the UDP segment with a zero checksum placeholder.
    std::vector<std::uint8_t> udp;
    udp.reserve(udp_length);
    appendBe16(udp, src_port);
    appendBe16(udp, dst_port);
    appendBe16(udp, udp_length);
    appendBe16(udp, 0x0000);  // Checksum placeholder
    if (payload != nullptr && payload_len > 0) {
        udp.insert(udp.end(), payload, payload + payload_len);
    }

    // Pseudo-header (12 B) for checksum: src_ip, dst_ip, zero, proto,
    // udp_length. IP addresses are in network byte order already.
    std::vector<std::uint8_t> region;
    region.reserve(12U + udp.size());
    for (int i = 0; i < 4; ++i) {
        region.push_back(static_cast<std::uint8_t>((src_ip_be >> (i * 8)) & 0xFFU));
    }
    for (int i = 0; i < 4; ++i) {
        region.push_back(static_cast<std::uint8_t>((dst_ip_be >> (i * 8)) & 0xFFU));
    }
    region.push_back(0x00);
    region.push_back(kIpProtoUdp);
    appendBe16(region, udp_length);
    region.insert(region.end(), udp.begin(), udp.end());

    std::uint16_t csum = inetChecksum(region.data(), region.size());
    // RFC 768 §Format: if the computed checksum is zero, transmit 0xFFFF
    // so the wire never carries the 0x0000 "checksum not computed"
    // sentinel ambiguously. Receivers treat 0xFFFF and 0x0000 as the
    // same one's-complement zero at validation.
    if (csum == 0x0000U) {
        csum = 0xFFFFU;
    }
    udp[6] = static_cast<std::uint8_t>((csum >> 8) & 0xFFU);
    udp[7] = static_cast<std::uint8_t>(csum & 0xFFU);

    // Apply overrides AFTER compute so the wire bytes deviate from
    // conformance in exactly the asserted axis (UDP_FIELDS_09/_10/_15/_16).
    if (overrides.length_field.has_value()) {
        const std::uint16_t v = overrides.length_field.value();
        udp[4] = static_cast<std::uint8_t>((v >> 8) & 0xFFU);
        udp[5] = static_cast<std::uint8_t>(v & 0xFFU);
    }
    if (overrides.checksum_field.has_value()) {
        const std::uint16_t v = overrides.checksum_field.value();
        udp[6] = static_cast<std::uint8_t>((v >> 8) & 0xFFU);
        udp[7] = static_cast<std::uint8_t>(v & 0xFFU);
    }
    if (overrides.truncate_to.has_value()) {
        const std::size_t t = overrides.truncate_to.value();
        if (t < udp.size()) {
            udp.resize(t);
        }
    }
    return udp;
}

std::vector<std::uint8_t> buildUdpDatagram(std::uint32_t src_ip_be,
                                           std::uint32_t dst_ip_be,
                                           std::uint16_t src_port,
                                           std::uint16_t dst_port,
                                           const std::uint8_t *payload,
                                           std::size_t        payload_len) {
    return buildUdpDatagramWithOverrides(src_ip_be, dst_ip_be, src_port,
                                          dst_port, payload, payload_len,
                                          UdpDatagramOverrides{});
}

}  // namespace tc8::stimulus
