#include "tc8/wire/icmp_echo.h"

#include "tc8/wire/ip_checksum.h"

namespace tc8::wire {

namespace {

constexpr std::uint8_t kIcmpTypeEchoRequest = 8;
constexpr std::uint8_t kIcmpCodeEchoRequest = 0;
constexpr std::uint8_t kIcmpv6TypeEchoRequest = 128;  // RFC 4443 §4.1
constexpr std::uint8_t kIcmpv6CodeEchoRequest = 0;

void appendBe16(std::vector<std::uint8_t> &b, std::uint16_t v) {
    b.push_back(static_cast<std::uint8_t>((v >> 8) & 0xFFU));
    b.push_back(static_cast<std::uint8_t>(v & 0xFFU));
}

// The 8-byte ICMP/ICMPv6 echo header (type, code, zero checksum placeholder,
// identifier, sequence) followed by `data`. The checksum is left zero here: the
// IPv4 caller patches it in (RFC 1071 over the whole body), the ICMPv6 caller
// leaves it for the kernel (it spans the IPv6 pseudo-header). The header layout
// is identical for both, so this is the single place the echo body is framed.
std::vector<std::uint8_t> buildEchoFrame(std::uint8_t type, std::uint8_t code, std::uint16_t id,
                                         std::uint16_t seq, const std::uint8_t *data,
                                         std::uint32_t data_len) {
    std::vector<std::uint8_t> icmp;
    icmp.reserve(8U + data_len);
    icmp.push_back(type);
    icmp.push_back(code);
    appendBe16(icmp, 0x0000);  // checksum placeholder
    appendBe16(icmp, id);
    appendBe16(icmp, seq);
    if (data_len > 0 && data != nullptr) {
        icmp.insert(icmp.end(), data, data + data_len);
    }
    return icmp;
}

}  // namespace

std::vector<std::uint8_t> buildIcmpEchoRequestBody(std::uint16_t id, std::uint16_t seq,
                                                   const std::uint8_t *data, std::uint32_t data_len,
                                                   std::optional<std::uint8_t> type_override,
                                                   std::optional<std::uint8_t> code_override,
                                                   bool corrupt_checksum) {
    std::vector<std::uint8_t> icmp =
        buildEchoFrame(type_override.value_or(kIcmpTypeEchoRequest),
                       code_override.value_or(kIcmpCodeEchoRequest), id, seq, data, data_len);

    std::uint16_t icmp_csum = inetChecksum(icmp.data(), icmp.size());
    if (corrupt_checksum) {
        // Flip one bit so the DUT's kernel rejects the frame (RFC 1122 / RFC 791 §3.2.2).
        icmp_csum = static_cast<std::uint16_t>(icmp_csum ^ 0x0001U);
    }
    icmp[2] = static_cast<std::uint8_t>((icmp_csum >> 8) & 0xFFU);
    icmp[3] = static_cast<std::uint8_t>(icmp_csum & 0xFFU);
    return icmp;
}

std::vector<std::uint8_t> buildIcmpv6EchoRequestBody(std::uint16_t id, std::uint16_t seq,
                                                     const std::uint8_t *data,
                                                     std::uint32_t data_len) {
    // Checksum stays the zero buildEchoFrame leaves: the IPPROTO_ICMPV6 socket
    // computes it over the IPv6 pseudo-header (RFC 4443 §2.3) — see the header.
    return buildEchoFrame(kIcmpv6TypeEchoRequest, kIcmpv6CodeEchoRequest, id, seq, data, data_len);
}

}  // namespace tc8::wire
