#include "stimulus/ipv4_frame_builder.h"

#include "wire/ip_checksum.h"

#include <cstdint>
#include <cstring>
#include <thread>

#include "stimulus/arp_builder.h"

namespace tc8::stimulus {

namespace {

constexpr std::uint16_t kEtherTypeIpv4 = 0x0800;
constexpr std::uint8_t  kIcmpTypeEchoRequest = 8;
constexpr std::uint8_t  kIcmpCodeEchoRequest = 0;
constexpr std::uint8_t  kIcmpTypeTimestampRequest = 13;
constexpr std::uint8_t  kIcmpCodeTimestampRequest = 0;

void appendBe32(std::vector<std::uint8_t> &b, std::uint32_t v) {
    b.push_back(static_cast<std::uint8_t>((v >> 24) & 0xFFU));
    b.push_back(static_cast<std::uint8_t>((v >> 16) & 0xFFU));
    b.push_back(static_cast<std::uint8_t>((v >> 8)  & 0xFFU));
    b.push_back(static_cast<std::uint8_t>(v         & 0xFFU));
}

void appendBe16(std::vector<std::uint8_t> &b, std::uint16_t v) {
    b.push_back(static_cast<std::uint8_t>((v >> 8) & 0xFFU));
    b.push_back(static_cast<std::uint8_t>(v & 0xFFU));
}

void appendIpv4Be(std::vector<std::uint8_t> &b, std::uint32_t ip_be) {
    b.push_back(static_cast<std::uint8_t>((ip_be >> 0) & 0xFFU));
    b.push_back(static_cast<std::uint8_t>((ip_be >> 8) & 0xFFU));
    b.push_back(static_cast<std::uint8_t>((ip_be >> 16) & 0xFFU));
    b.push_back(static_cast<std::uint8_t>((ip_be >> 24) & 0xFFU));
}

using ::tc8::wire::inetChecksum;

}  // namespace

std::vector<std::uint8_t> buildIpv4Frame(const Ipv4FrameSpec &spec,
                                         const std::vector<std::uint8_t> &ip_payload) {
    // IPv4 options are 4-byte aligned in the header. Pad with EOL
    // (0x00) bytes so the options segment reaches a 4-byte boundary;
    // the caller owns the option's own length-byte semantics. With
    // empty options the padding computation collapses to zero → IHL
    // stays at 5.
    const std::size_t options_raw_len = spec.ip_options.size();
    const std::size_t options_padding = (4U - (options_raw_len % 4U)) % 4U;
    const std::size_t options_total   = options_raw_len + options_padding;
    const std::size_t ip_header_len   = 20U + options_total;
    const std::size_t ip_payload_len  = ip_payload.size();
    const std::size_t ip_total_len    = ip_header_len + ip_payload_len;

    std::vector<std::uint8_t> frame;
    frame.reserve(14 + ip_total_len);

    // Ethernet II header (14 B).
    frame.insert(frame.end(), spec.dst_mac.begin(), spec.dst_mac.end());
    frame.insert(frame.end(), spec.src_mac.begin(), spec.src_mac.end());
    appendBe16(frame, kEtherTypeIpv4);

    // IPv4 header (20 B fixed + options + padding). Construct into a
    // scratch buffer first so the header checksum can be computed
    // before the bytes are appended to the outbound frame. IHL is
    // derived from the full header length including options, so the
    // default (no options) still emits 0x45.
    const std::uint8_t ihl_words = static_cast<std::uint8_t>(ip_header_len / 4U);
    std::vector<std::uint8_t> ip_hdr;
    ip_hdr.reserve(ip_header_len);
    ip_hdr.push_back(static_cast<std::uint8_t>(0x40U | (ihl_words & 0x0FU)));  // Version=4, IHL=ihl_words
    ip_hdr.push_back(0x00);  // DSCP+ECN
    appendBe16(ip_hdr, static_cast<std::uint16_t>(ip_total_len));
    appendBe16(ip_hdr, spec.ip_id);
    // Flags + Fragment Offset (byte[6..7]). Reserved + DF always 0.
    // MF sits in bit 5 of byte[6]; offset occupies low 13 bits across
    // byte[6..7] in 8-octet units (RFC 791 §3.1). The default
    // (MF=0, offset=0) reproduces the pre-fragment-knob 0x0000
    // encoding.
    {
        const std::uint16_t offset_masked =
            static_cast<std::uint16_t>(spec.fragment_offset & 0x1FFFU);
        const std::uint8_t flags_high = static_cast<std::uint8_t>(
            (spec.more_fragments ? 0x20U : 0U) |
            static_cast<std::uint8_t>((offset_masked >> 8) & 0x1FU));
        ip_hdr.push_back(flags_high);
        ip_hdr.push_back(static_cast<std::uint8_t>(offset_masked & 0xFFU));
    }
    ip_hdr.push_back(spec.ttl);
    ip_hdr.push_back(spec.ip_protocol);
    appendBe16(ip_hdr, 0x0000);  // Checksum placeholder
    appendIpv4Be(ip_hdr, spec.src_ip);
    appendIpv4Be(ip_hdr, spec.dst_ip);
    // Options + EOL padding. Empty vector → no bytes pushed, checksum
    // path below sees the canonical 20 B header.
    ip_hdr.insert(ip_hdr.end(), spec.ip_options.begin(), spec.ip_options.end());
    ip_hdr.insert(ip_hdr.end(), options_padding, std::uint8_t{0x00});

    // Apply per-field header overrides BEFORE checksum computation so
    // the resulting header carries a valid checksum over the overridden
    // bytes.
    if (spec.version_override) {
        // High nibble of byte 0 = Version. Preserve IHL nibble (low 4
        // bits) so the header length declaration stays well-formed.
        ip_hdr[0] = static_cast<std::uint8_t>(
            ((*spec.version_override & 0x0FU) << 4) | (ip_hdr[0] & 0x0FU));
    }
    if (spec.ihl_override) {
        // Low nibble of byte 0 = IHL (32-bit words). Preserve version
        // nibble (high 4 bits) so the wire still claims IPv4.
        ip_hdr[0] = static_cast<std::uint8_t>(
            (ip_hdr[0] & 0xF0U) | (*spec.ihl_override & 0x0FU));
    }
    if (spec.total_length_override) {
        ip_hdr[2] = static_cast<std::uint8_t>((*spec.total_length_override >> 8) & 0xFFU);
        ip_hdr[3] = static_cast<std::uint8_t>(*spec.total_length_override & 0xFFU);
    }

    // Overwrite placeholder with computed IPv4 header checksum.
    std::uint16_t ip_csum = inetChecksum(ip_hdr.data(), ip_hdr.size());
    if (spec.corrupt_ip_checksum) {
        // Flip one bit post-compute. XOR of 0x0001 avoids producing
        // 0xFFFF (the UDP "checksum not computed" sentinel).
        ip_csum = static_cast<std::uint16_t>(ip_csum ^ 0x0001U);
    }
    ip_hdr[10] = static_cast<std::uint8_t>((ip_csum >> 8) & 0xFFU);
    ip_hdr[11] = static_cast<std::uint8_t>(ip_csum & 0xFFU);
    frame.insert(frame.end(), ip_hdr.begin(), ip_hdr.end());

    // IP payload — caller-supplied bytes verbatim.
    frame.insert(frame.end(), ip_payload.begin(), ip_payload.end());

    return frame;
}

int emitIpv4Frame(std::string_view iface,
                  const Ipv4FrameSpec &spec,
                  const std::vector<std::uint8_t> &ip_payload,
                  const IpBootTiming &timing) {
    if (timing.initial_wait.count() > 0) {
        std::this_thread::sleep_for(timing.initial_wait);
    }
    const auto frame = buildIpv4Frame(spec, ip_payload);
    const int rc = sendRawEthernet(frame, iface);
    if (timing.post_send_wait.count() > 0) {
        std::this_thread::sleep_for(timing.post_send_wait);
    }
    return rc;
}

std::vector<std::uint8_t> buildIcmpEchoRequestBody(
    std::uint16_t       id,
    std::uint16_t       seq,
    const std::uint8_t *data,
    std::uint32_t       data_len,
    std::optional<std::uint8_t> type_override,
    std::optional<std::uint8_t> code_override,
    bool                corrupt_checksum) {
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
        // Flip one bit so the DUT's kernel rejects the frame per RFC
        // 1122 §3.2.2.
        icmp_csum = static_cast<std::uint16_t>(icmp_csum ^ 0x0001U);
    }
    icmp[2] = static_cast<std::uint8_t>((icmp_csum >> 8) & 0xFFU);
    icmp[3] = static_cast<std::uint8_t>(icmp_csum & 0xFFU);
    return icmp;
}

std::vector<std::uint8_t> buildIcmpTimestampRequestBody(
    std::uint16_t id,
    std::uint16_t seq,
    std::uint32_t originate_timestamp,
    std::uint32_t receive_timestamp,
    std::uint32_t transmit_timestamp,
    std::optional<std::uint8_t> type_override,
    std::optional<std::uint8_t> code_override,
    bool          corrupt_checksum) {
    std::vector<std::uint8_t> icmp;
    icmp.reserve(20U);
    icmp.push_back(type_override.value_or(kIcmpTypeTimestampRequest));
    icmp.push_back(code_override.value_or(kIcmpCodeTimestampRequest));
    appendBe16(icmp, 0x0000);  // Checksum placeholder
    appendBe16(icmp, id);
    appendBe16(icmp, seq);
    appendBe32(icmp, originate_timestamp);
    appendBe32(icmp, receive_timestamp);
    appendBe32(icmp, transmit_timestamp);

    std::uint16_t icmp_csum = inetChecksum(icmp.data(), icmp.size());
    if (corrupt_checksum) {
        icmp_csum = static_cast<std::uint16_t>(icmp_csum ^ 0x0001U);
    }
    icmp[2] = static_cast<std::uint8_t>((icmp_csum >> 8) & 0xFFU);
    icmp[3] = static_cast<std::uint8_t>(icmp_csum & 0xFFU);
    return icmp;
}

}  // namespace tc8::stimulus
