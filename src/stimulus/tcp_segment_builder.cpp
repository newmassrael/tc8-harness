#include "stimulus/tcp_segment_builder.h"

#include "tc8/wire/ip_checksum.h"

namespace tc8::stimulus {

namespace {

constexpr std::uint8_t kIpProtoTcp = 0x06;

void appendBe16(std::vector<std::uint8_t> &b, std::uint16_t v) {
    b.push_back(static_cast<std::uint8_t>((v >> 8) & 0xFFU));
    b.push_back(static_cast<std::uint8_t>(v & 0xFFU));
}

void appendBe32(std::vector<std::uint8_t> &b, std::uint32_t v) {
    b.push_back(static_cast<std::uint8_t>((v >> 24) & 0xFFU));
    b.push_back(static_cast<std::uint8_t>((v >> 16) & 0xFFU));
    b.push_back(static_cast<std::uint8_t>((v >> 8)  & 0xFFU));
    b.push_back(static_cast<std::uint8_t>( v        & 0xFFU));
}

using ::tc8::wire::inetChecksum;

}  // namespace

std::vector<std::uint8_t> buildTcpSegment(std::uint32_t src_ip_be,
                                          std::uint32_t dst_ip_be,
                                          const TcpSegmentSpec &spec) {
    // Pad options to a 4-byte boundary with NOP (kind 1). EOL (kind 0)
    // would also work, but NOP is unambiguous if the DUT scans past the
    // Data Offset line: EOL tells a parser "stop scanning options", NOP
    // tells it "skip this byte" — either is spec-legal as padding, but
    // NOP is the conventional choice (tcpdump/wireshark display them
    // as padding rather than truncating the option list).
    std::vector<std::uint8_t> opts = spec.options;
    while ((opts.size() % 4U) != 0U) {
        opts.push_back(0x01U);  // NOP
    }

    const std::uint8_t  data_offset_words =
        static_cast<std::uint8_t>((20U + opts.size()) / 4U);
    const std::uint16_t tcp_length =
        static_cast<std::uint16_t>(20U + opts.size() + spec.payload.size());

    std::vector<std::uint8_t> seg;
    seg.reserve(tcp_length);
    appendBe16(seg, spec.src_port);
    appendBe16(seg, spec.dst_port);
    appendBe32(seg, spec.seq_num);
    appendBe32(seg, spec.ack_num);
    // Byte 12: Data Offset (high 4 bits) + reserved 4 bits (low).
    // §4.8.6.X TCP_HEADER_07/08 override the data_offset to a value
    // disjoint from the encoded segment length (less-than-5 / greater-
    // than-actual) so Linux's `tcp_v4_rcv` falls into the bad_packet
    // / pskb_may_pull-fail discard paths. §4.8.6.X TCP_HEADER_06
    // overrides the reserved nibble to 0xF to assert RFC 4413 §4.2.3
    // ignore-on-receive. Both overrides leave the rest of the segment
    // (and the still-computed checksum) intact so the spec-asserted
    // discard reason is the field under test.
    const std::uint8_t encoded_doff = spec.data_offset_override.has_value()
        ? *spec.data_offset_override
        : data_offset_words;
    const std::uint8_t encoded_reserved = spec.reserved_override.has_value()
        ? static_cast<std::uint8_t>(*spec.reserved_override & 0x0FU)
        : 0x00U;
    seg.push_back(static_cast<std::uint8_t>(
        ((encoded_doff << 4) & 0xF0U) | encoded_reserved));
    seg.push_back(spec.flags);
    appendBe16(seg, spec.window);
    appendBe16(seg, 0x0000U);                 // checksum placeholder
    appendBe16(seg, spec.urgent_pointer);
    if (!opts.empty()) {
        seg.insert(seg.end(), opts.begin(), opts.end());
    }
    if (!spec.payload.empty()) {
        seg.insert(seg.end(), spec.payload.begin(), spec.payload.end());
    }

    // RFC 793 pseudo-header: src_ip + dst_ip + zero + protocol + tcp_length.
    std::vector<std::uint8_t> region;
    region.reserve(12U + seg.size());
    for (int i = 0; i < 4; ++i) {
        region.push_back(
            static_cast<std::uint8_t>((src_ip_be >> (i * 8)) & 0xFFU));
    }
    for (int i = 0; i < 4; ++i) {
        region.push_back(
            static_cast<std::uint8_t>((dst_ip_be >> (i * 8)) & 0xFFU));
    }
    region.push_back(0x00U);
    region.push_back(kIpProtoTcp);
    appendBe16(region, tcp_length);
    region.insert(region.end(), seg.begin(), seg.end());

    std::uint16_t csum = inetChecksum(region.data(), region.size());
    if (spec.corrupt_tcp_checksum) {
        // §4.8.6.2 TCP_CHECKSUM_02 spec literal "incorrect checksum".
        // XOR 0x0001 (low bit flip) is the smallest deterministic
        // perturbation that makes the segment fail RFC 793's pseudo-
        // header validation; same shape as `Ipv4FrameSpec::corrupt_
        // ip_checksum`. Avoids 0xFFFF accidentally collapsing to 0x0000
        // (RFC 768 UDP "no checksum" sentinel) — TCP has no such
        // sentinel, so it would still be rejected, but staying clear of
        // it keeps this consistent with the IPv4 builder convention.
        csum = static_cast<std::uint16_t>(csum ^ 0x0001U);
    }
    if (spec.force_zero_tcp_checksum) {
        // §4.8.6.X TCP_HEADER_09 spec literal "Checksum = 0". Distinct
        // from corrupt_tcp_checksum: this forces the absolute 0x0000
        // sentinel rather than an arbitrary wrong sum. Applied AFTER
        // corrupt_tcp_checksum so a caller pinning both flags lands
        // on zero (the more specific assertion wins).
        csum = 0x0000U;
    }
    seg[16] = static_cast<std::uint8_t>((csum >> 8) & 0xFFU);
    seg[17] = static_cast<std::uint8_t>(csum & 0xFFU);
    return seg;
}

}  // namespace tc8::stimulus
