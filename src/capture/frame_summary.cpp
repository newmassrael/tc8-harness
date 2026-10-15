#include "capture/frame_summary.h"

#include <cstring>

namespace tc8::capture {

namespace {

constexpr std::size_t kEthHeader = 14;
constexpr std::size_t kVlanTag = 4;
constexpr std::uint16_t kEtherIpv4 = 0x0800;
constexpr std::uint16_t kEtherArp = 0x0806;
constexpr std::size_t kIpv4MinHeader = 20;
constexpr std::size_t kArpIpv4Size = 28;
constexpr std::uint8_t kIpProtoTcp = 6;
constexpr std::uint8_t kIpProtoUdp = 17;

std::uint16_t be16(const std::uint8_t *p) {
    return static_cast<std::uint16_t>((p[0] << 8) | p[1]);
}

bool isVlanTpid(std::uint16_t t) {
    return t == 0x8100 || t == 0x88a8 || t == 0x9100;
}

std::uint32_t rawBe32(const std::uint8_t *p) {
    std::uint32_t v;
    std::memcpy(&v, p, sizeof(v));
    return v;
}

}  // namespace

::tc8::FrameSummary summarizeEthernetFrame(const std::uint8_t *data, std::size_t caplen,
                                           std::uint32_t wire_len) {
    ::tc8::FrameSummary s;
    s.wire_len = wire_len;
    if (caplen < kEthHeader) {
        return s;
    }

    std::size_t off = 12;
    std::uint16_t ethertype = be16(data + off);
    // The tester's own VLAN-aware capture filter admits tagged frames, so a tag is
    // part of normal traffic: step over it (a stacked pair at most) to the payload type.
    for (int tags = 0; tags < 2 && isVlanTpid(ethertype); ++tags) {
        if (caplen < off + 2 + kVlanTag) {
            return s;
        }
        off += kVlanTag;
        ethertype = be16(data + off);
    }
    const std::size_t l3 = off + 2;

    if (ethertype == kEtherArp) {
        // hardware type 1 (Ethernet), protocol type IPv4, sizes 6 and 4.
        if (caplen >= l3 + kArpIpv4Size && be16(data + l3) == 1 &&
            be16(data + l3 + 2) == kEtherIpv4 && data[l3 + 4] == 6 && data[l3 + 5] == 4) {
            s.has_ips = true;
            s.src_ip_be = rawBe32(data + l3 + 14);
            s.dst_ip_be = rawBe32(data + l3 + 24);
        }
        return s;
    }
    if (ethertype != kEtherIpv4 || caplen < l3 + kIpv4MinHeader || (data[l3] >> 4) != 4) {
        return s;
    }

    const std::size_t ihl = static_cast<std::size_t>(data[l3] & 0x0f) * 4;
    s.has_ips = true;
    s.src_ip_be = rawBe32(data + l3 + 12);
    s.dst_ip_be = rawBe32(data + l3 + 16);

    const std::uint8_t proto = data[l3 + 9];
    if (proto == kIpProtoUdp) {
        s.proto = ::tc8::FrameSummary::Proto::kUdp;
    } else if (proto == kIpProtoTcp) {
        s.proto = ::tc8::FrameSummary::Proto::kTcp;
    } else {
        return s;
    }

    // The ports live in the first fragment only, and only if the captured bytes reach
    // them past a header that may carry options.
    const bool first_fragment = (be16(data + l3 + 6) & 0x1fff) == 0;
    const std::size_t l4 = l3 + ihl;
    if (first_fragment && ihl >= kIpv4MinHeader && caplen >= l4 + 4) {
        s.has_ports = true;
        s.src_port = be16(data + l4);
        s.dst_port = be16(data + l4 + 2);
    }
    return s;
}

::tc8::FrameSummary summarizePcapRecord(const pcap_pkthdr &hdr, const u_char *bytes, bool nano) {
    ::tc8::FrameSummary f = summarizeEthernetFrame(bytes, hdr.caplen, hdr.len);
    f.t_us = static_cast<std::int64_t>(hdr.ts.tv_sec) * 1000000 +
             (nano ? hdr.ts.tv_usec / 1000 : hdr.ts.tv_usec);
    return f;
}

}  // namespace tc8::capture
