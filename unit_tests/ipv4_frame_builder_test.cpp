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

TEST(BuildIcmpEchoRequestBody, DefaultSizeIs8Bytes) {
    // 8 B ICMP header, no payload. FRAGMENTS_04 splits this across
    // two fragments — the first half is the 8 B header. With no data
    // the body is exactly that and can't be split, so FRAGMENTS_01-04
    // callers pass a non-empty `data` that makes each half >= 8 B.
    const auto body = buildIcmpEchoRequestBody(0x1234, 0x5678, nullptr, 0);
    EXPECT_EQ(body.size(), 8u);
}

TEST(BuildIcmpEchoRequestBody, IdAndSeqInBigEndian) {
    // The DUT's Echo Reply echoes id/seq verbatim; FRAGMENTS_01
    // asserts they match. Wire ordering is big-endian per RFC 792 —
    // guards against host-endianness bugs on LE platforms.
    const auto body = buildIcmpEchoRequestBody(0xAABB, 0xCCDD, nullptr, 0);
    ASSERT_EQ(body.size(), 8u);
    EXPECT_EQ(body[4], 0xAAU);
    EXPECT_EQ(body[5], 0xBBU);
    EXPECT_EQ(body[6], 0xCCU);
    EXPECT_EQ(body[7], 0xDDU);
}

TEST(BuildIcmpEchoRequestBody, PayloadAppendsAfterHeader) {
    // FRAGMENTS_01's reassembly-validation relies on the DUT reading
    // the full reassembled body. The body helper must emit
    // header-then-payload contiguously so `buildIpv4Frame(frag_N,
    // body_slice_N)` yields the expected on-wire bytes.
    const std::array<std::uint8_t, 8> payload{1, 2, 3, 4, 5, 6, 7, 8};
    const auto body = buildIcmpEchoRequestBody(
        0x1234, 0x5678, payload.data(), payload.size());
    ASSERT_EQ(body.size(), 8u + payload.size());
    EXPECT_EQ(std::memcmp(body.data() + 8, payload.data(), payload.size()), 0);
}

TEST(BuildIcmpEchoRequestBody, ChecksumCoversFullBodyIncludingPayload) {
    // The DUT validates the ICMP checksum over the reassembled body.
    // FRAGMENTS_01 computes ONE checksum over the 16 B body, splits
    // 8/8 across two fragments — the reassembled datagram must
    // validate. If the helper's checksum scope drifted to header-
    // only, the DUT would drop after reassembly and FRAGMENTS_01
    // would false-fail.
    const std::array<std::uint8_t, 8> payload{0x10, 0x20, 0x30, 0x40,
                                              0x50, 0x60, 0x70, 0x80};
    const auto body = buildIcmpEchoRequestBody(
        0x1234, 0x5678, payload.data(), payload.size());
    EXPECT_EQ(checksumRef(body.data(), body.size()), 0u);
}

TEST(BuildIcmpEchoRequestBody, TypeOverrideReplacesByteZero) {
    // Information Request (type=15) path — the same body helper
    // serves TYPE_16 via the override. Parallels the
    // `IcmpMessageSpec::icmp_type_override` coverage in
    // icmpv4_builder_test but on the layered helper.
    const auto body = buildIcmpEchoRequestBody(
        0x1234, 0x5678, nullptr, 0, std::uint8_t{15}, std::uint8_t{0});
    ASSERT_EQ(body.size(), 8u);
    EXPECT_EQ(body[0], 15U);
    EXPECT_EQ(body[1], 0U);
}

TEST(BuildIcmpEchoRequestBody, CorruptChecksumFlagProducesNonZeroSum) {
    // TYPE_10 path. Post-compute XOR must produce a body whose
    // running-sum is non-zero — exactly what the DUT kernel uses to
    // reject the frame.
    const auto body = buildIcmpEchoRequestBody(
        0x1234, 0x5678, nullptr, 0,
        std::nullopt, std::nullopt, /*corrupt_checksum=*/true);
    EXPECT_NE(checksumRef(body.data(), body.size()), 0u);
}

}  // namespace
}  // namespace tc8::stimulus
