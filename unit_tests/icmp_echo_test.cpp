#include <array>
#include <cstddef>
#include <cstdint>
#include <cstring>
#include <optional>
#include <vector>

#include <gtest/gtest.h>

#include "tc8/wire/icmp_echo.h"

namespace tc8::wire {
namespace {

// Independent RFC 1071 reference — deliberately NOT tc8::wire::inetChecksum, so
// these tests validate the echo body against a second implementation rather than
// against the one under test. Running it across a body that already carries its
// checksum must return 0.
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

TEST(BuildIcmpEchoRequestBody, DefaultSizeIs8Bytes) {
    // 8 B ICMP header, no payload. FRAGMENTS_04 splits this across two
    // fragments — the first half is the 8 B header.
    const auto body = buildIcmpEchoRequestBody(0x1234, 0x5678, nullptr, 0);
    EXPECT_EQ(body.size(), 8u);
}

TEST(BuildIcmpEchoRequestBody, IdAndSeqInBigEndian) {
    // The DUT's Echo Reply echoes id/seq verbatim; FRAGMENTS_01 asserts they
    // match. Wire ordering is big-endian per RFC 792 — guards against
    // host-endianness bugs on LE platforms.
    const auto body = buildIcmpEchoRequestBody(0xAABB, 0xCCDD, nullptr, 0);
    ASSERT_EQ(body.size(), 8u);
    EXPECT_EQ(body[4], 0xAAU);
    EXPECT_EQ(body[5], 0xBBU);
    EXPECT_EQ(body[6], 0xCCU);
    EXPECT_EQ(body[7], 0xDDU);
}

TEST(BuildIcmpEchoRequestBody, PayloadAppendsAfterHeader) {
    // The body helper must emit header-then-payload contiguously so
    // buildIpv4Frame(frag_N, body_slice_N) yields the expected on-wire bytes.
    const std::array<std::uint8_t, 8> payload{1, 2, 3, 4, 5, 6, 7, 8};
    const auto body = buildIcmpEchoRequestBody(0x1234, 0x5678, payload.data(), payload.size());
    ASSERT_EQ(body.size(), 8u + payload.size());
    EXPECT_EQ(std::memcmp(body.data() + 8, payload.data(), payload.size()), 0);
}

TEST(BuildIcmpEchoRequestBody, ChecksumCoversFullBodyIncludingPayload) {
    // FRAGMENTS_01 computes ONE checksum over the 16 B body, splits 8/8 across
    // two fragments — the reassembled datagram must validate. If the checksum
    // scope drifted to header-only, the DUT would drop after reassembly.
    const std::array<std::uint8_t, 8> payload{0x10, 0x20, 0x30, 0x40, 0x50, 0x60, 0x70, 0x80};
    const auto body = buildIcmpEchoRequestBody(0x1234, 0x5678, payload.data(), payload.size());
    EXPECT_EQ(checksumRef(body.data(), body.size()), 0u);
}

TEST(BuildIcmpEchoRequestBody, TypeOverrideReplacesByteZero) {
    // Information Request (type=15) path — the same body helper serves TYPE_16
    // via the override.
    const auto body =
        buildIcmpEchoRequestBody(0x1234, 0x5678, nullptr, 0, std::uint8_t{15}, std::uint8_t{0});
    ASSERT_EQ(body.size(), 8u);
    EXPECT_EQ(body[0], 15U);
    EXPECT_EQ(body[1], 0U);
}

TEST(BuildIcmpEchoRequestBody, CorruptChecksumFlagProducesNonZeroSum) {
    // TYPE_10 path. Post-compute XOR must produce a body whose running-sum is
    // non-zero — exactly what the DUT kernel uses to reject the frame.
    const auto body = buildIcmpEchoRequestBody(0x1234, 0x5678, nullptr, 0, std::nullopt,
                                               std::nullopt, /*corrupt_checksum=*/true);
    EXPECT_NE(checksumRef(body.data(), body.size()), 0u);
}

TEST(BuildIcmpv6EchoRequestBody, HeaderTypeCodeAndZeroChecksum) {
    // ICMPv6 Echo Request is type 128 / code 0 (RFC 4443 §4.1). The checksum
    // field stays zero: the IPPROTO_ICMPV6 socket fills it over the IPv6
    // pseudo-header (RFC 4443 §2.3), so a body-local sum would only be
    // overwritten. id/seq keep the big-endian layout shared with the IPv4 echo.
    const std::array<std::uint8_t, 4> payload{0xDE, 0xAD, 0xBE, 0xEF};
    const auto body = buildIcmpv6EchoRequestBody(0xAABB, 0xCCDD, payload.data(), payload.size());
    ASSERT_EQ(body.size(), 8u + payload.size());
    EXPECT_EQ(body[0], 128U);   // type
    EXPECT_EQ(body[1], 0U);     // code
    EXPECT_EQ(body[2], 0U);     // checksum high byte — left zero
    EXPECT_EQ(body[3], 0U);     // checksum low byte — left zero
    EXPECT_EQ(body[4], 0xAAU);  // id, big-endian
    EXPECT_EQ(body[5], 0xBBU);
    EXPECT_EQ(body[6], 0xCCU);  // seq, big-endian
    EXPECT_EQ(body[7], 0xDDU);
    EXPECT_EQ(std::memcmp(body.data() + 8, payload.data(), payload.size()), 0);
}

}  // namespace
}  // namespace tc8::wire
