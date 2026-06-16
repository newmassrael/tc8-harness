#include <array>
#include <cstdint>
#include <cstring>
#include <vector>

#include <gtest/gtest.h>

#include "stimulus/ipv4_frame_builder.h"

namespace tc8::stimulus {
namespace {

constexpr std::uint32_t kTesterIpBe = 0x010010AC;  // 172.16.0.1
constexpr std::uint32_t kDutIpBe    = 0x020010AC;  // 172.16.0.2
constexpr std::array<std::uint8_t, 6> kDstMac{0xDE, 0xAD, 0xBE, 0xEF, 0x00, 0x01};

Ipv4FrameSpec makeBaseSpec() {
    Ipv4FrameSpec s{};
    s.dst_mac = kDstMac;
    s.src_ip  = kTesterIpBe;
    s.dst_ip  = kDutIpBe;
    return s;
}

std::uint16_t checksumRef(const std::uint8_t *data, std::size_t len) {
    std::uint32_t sum = 0;
    std::size_t i = 0;
    for (; i + 1 < len; i += 2) {
        sum += static_cast<std::uint32_t>((data[i] << 8) | data[i + 1]);
    }
    if (i < len) {
        sum += static_cast<std::uint32_t>(data[i]) << 8;
    }
    while ((sum >> 16) != 0U) {
        sum = (sum & 0xFFFFU) + (sum >> 16);
    }
    return static_cast<std::uint16_t>(~sum & 0xFFFFU);
}

// Ipv4FrameSpec is the new canonical IP-layer shape. These tests pin
// the contract the ICMP-layer builder and every future §4.4 stimulus
// (FRAGMENTS, REASSEMBLY, UDP-based ADDRESSING_01/02) depends on.
// `buildIcmpMessage` is rewritten on top of this; the icmpv4 tests
// already cover that composition, so these tests only guard the
// primitives a caller that bypasses `IcmpMessageSpec` would use.

TEST(BuildIpv4Frame, EmptyPayloadIsHeadersOnly) {
    // 14 Eth + 20 IP + 0 payload = 34 B. Smallest valid frame the
    // builder emits. FRAGMENTS reuses this shape with payload growing
    // per fragment slice.
    const auto b = buildIpv4Frame(makeBaseSpec(), {});
    EXPECT_EQ(b.size(), 34u);
}

TEST(BuildIpv4Frame, PayloadAppendsAfterHeader) {
    const std::vector<std::uint8_t> payload{0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88};
    const auto b = buildIpv4Frame(makeBaseSpec(), payload);
    ASSERT_EQ(b.size(), 34u + payload.size());
    EXPECT_EQ(std::memcmp(b.data() + 34, payload.data(), payload.size()), 0);
}

TEST(BuildIpv4Frame, TotalLengthCoversHeaderAndPayload) {
    // IP total_length must match the wire size the DUT sees. FRAGMENTS
    // consumers split an ICMP body across two `buildIpv4Frame` calls
    // so each fragment's total_length must reflect its own slice, not
    // the full reassembled ICMP packet.
    const std::vector<std::uint8_t> payload(24, 0xAB);
    const auto b = buildIpv4Frame(makeBaseSpec(), payload);
    ASSERT_GE(b.size(), 34u);
    EXPECT_EQ(b[16], 0x00U);
    EXPECT_EQ(b[17], 20U + 24U);  // 20 header + 24 payload
}

TEST(BuildIpv4Frame, IpProtocolByteReflectsSpec) {
    // §4.4.4.6 FRAGMENTS_04 — frag 1 carries ipType=TCP(6) so the
    // DUT's reassembly check rejects the fragment tuple. The builder
    // must honor arbitrary protocol numbers, not hardcode ICMP.
    auto spec = makeBaseSpec();
    spec.ip_protocol = kIpProtoTcp;
    const auto b = buildIpv4Frame(spec, {});
    ASSERT_GE(b.size(), 24u);
    EXPECT_EQ(b[23], kIpProtoTcp);
}

TEST(BuildIpv4Frame, DefaultProtocolIsIcmp) {
    // Regression guard: unset `ip_protocol` must default to ICMP so
    // every pre-FRAGMENTS caller path keeps its wire shape.
    const auto b = buildIpv4Frame(makeBaseSpec(), {});
    ASSERT_GE(b.size(), 24u);
    EXPECT_EQ(b[23], kIpProtoIcmp);
}

TEST(BuildIpv4Frame, FragmentFieldsEncode) {
    // §4.4.4.6 FRAGMENTS — frag 0 MF=1/offset=0, frag 1 MF=0/offset=
    // bytes/8. Independence check shared with icmpv4_builder_test but
    // on the layered call site so a future rename doesn't orphan
    // coverage.
    auto spec = makeBaseSpec();
    spec.more_fragments  = true;
    spec.fragment_offset = 185U;  // MTU-sized: 1480 / 8
    const auto b = buildIpv4Frame(spec, {});
    ASSERT_GE(b.size(), 34u);
    EXPECT_EQ(b[14 + 6], 0x20U);  // MF bit
    EXPECT_EQ(b[14 + 7], 185U);
}

TEST(BuildIpv4Frame, Ipv4ChecksumIsValid) {
    // RFC 1071 validation: running the one's-complement sum across
    // the header (including the checksum field in its final position)
    // must return 0. The FRAGMENTS stimulus relies on this — a bad IP
    // checksum would have the DUT drop the fragment for the wrong
    // reason, masking the reassembly invariant under test.
    const auto b = buildIpv4Frame(makeBaseSpec(), {});
    ASSERT_GE(b.size(), 34u);
    EXPECT_EQ(checksumRef(b.data() + 14, 20), 0u);
}

// The ICMP Echo Request body builder moved to the shared wire layer; its unit
// tests live with it in icmp_echo_test.cpp (tc8::wire::buildIcmpEchoRequestBody).

}  // namespace
}  // namespace tc8::stimulus
