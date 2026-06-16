#include "wire/icmp_echo.h"

#include "wire/ip_checksum.h"

namespace tc8::wire {

namespace {

constexpr std::uint8_t kIcmpTypeEchoRequest = 8;
constexpr std::uint8_t kIcmpCodeEchoRequest = 0;

void appendBe16(std::vector<std::uint8_t> &b, std::uint16_t v) {
    b.push_back(static_cast<std::uint8_t>((v >> 8) & 0xFFU));
    b.push_back(static_cast<std::uint8_t>(v & 0xFFU));
}

}  // namespace

std::vector<std::uint8_t> buildIcmpEchoRequestBody(std::uint16_t id, std::uint16_t seq,
                                                   const std::uint8_t *data, std::uint32_t data_len,
                                                   std::optional<std::uint8_t> type_override,
                                                   std::optional<std::uint8_t> code_override,
                                                   bool corrupt_checksum) {
    std::vector<std::uint8_t> icmp;
    icmp.reserve(8U + data_len);
    icmp.push_back(type_override.value_or(kIcmpTypeEchoRequest));
    icmp.push_back(code_override.value_or(kIcmpCodeEchoRequest));
    appendBe16(icmp, 0x0000);  // Checksum placeholder
    appendBe16(icmp, id);
    appendBe16(icmp, seq);
    if (data_len > 0 && data != nullptr) {
        icmp.insert(icmp.end(), data, data + data_len);
    }

    std::uint16_t icmp_csum = inetChecksum(icmp.data(), icmp.size());
    if (corrupt_checksum) {
        // Flip one bit so the DUT's kernel rejects the frame (RFC 1122 / RFC 791 §3.2.2).
        icmp_csum = static_cast<std::uint16_t>(icmp_csum ^ 0x0001U);
    }
    icmp[2] = static_cast<std::uint8_t>((icmp_csum >> 8) & 0xFFU);
    icmp[3] = static_cast<std::uint8_t>(icmp_csum & 0xFFU);
    return icmp;
}

}  // namespace tc8::wire
