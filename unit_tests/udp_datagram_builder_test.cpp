#include <array>
#include <cstdint>
#include <cstring>
#include <vector>

#include <gtest/gtest.h>

#include "stimulus/udp_datagram_builder.h"

namespace tc8::stimulus {
namespace {

constexpr std::uint32_t kTesterIpBe = 0x010010AC;  // 172.16.0.1
constexpr std::uint32_t kDutIpBe    = 0x020010AC;  // 172.16.0.2

// Reference checksum matching RFC 1071 one's-complement sum, used to
// verify the builder produces a datagram whose pseudo-header + UDP
// region running-sum collapses to zero (the validity invariant).
std::uint16_t runningSumRef(const std::uint8_t *data, std::size_t len) {
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
    return static_cast<std::uint16_t>(sum & 0xFFFFU);
}

TEST(BuildUdpDatagram, HeaderOnlyIs8Bytes) {
    const auto d = buildUdpDatagram(kTesterIpBe, kDutIpBe, 20001, 20000,
                                    nullptr, 0);
    EXPECT_EQ(d.size(), 8u);
}

TEST(BuildUdpDatagram, PortsAreBigEndian) {
    const auto d = buildUdpDatagram(kTesterIpBe, kDutIpBe, 0x1234, 0xABCD,
                                    nullptr, 0);
    ASSERT_EQ(d.size(), 8u);
    EXPECT_EQ(d[0], 0x12U);
    EXPECT_EQ(d[1], 0x34U);
    EXPECT_EQ(d[2], 0xABU);
    EXPECT_EQ(d[3], 0xCDU);
}

TEST(BuildUdpDatagram, LengthCoversHeaderAndPayload) {
    // RFC 768: Length = 8 B header + payload. The DUT uses this to
    // demarcate UDP's body from the IP payload region.
    const std::array<std::uint8_t, 5> payload{0x11, 0x22, 0x33, 0x44, 0x55};
    const auto d = buildUdpDatagram(kTesterIpBe, kDutIpBe, 1, 2,
                                    payload.data(), payload.size());
    ASSERT_GE(d.size(), 8u);
    EXPECT_EQ(d[4], 0x00U);
    EXPECT_EQ(d[5], 8u + payload.size());
}

TEST(BuildUdpDatagram, PayloadAppendsAfterHeader) {
    const std::array<std::uint8_t, 4> payload{0xDE, 0xAD, 0xBE, 0xEF};
    const auto d = buildUdpDatagram(kTesterIpBe, kDutIpBe, 1, 2,
                                    payload.data(), payload.size());
    ASSERT_EQ(d.size(), 8u + payload.size());
    EXPECT_EQ(std::memcmp(d.data() + 8, payload.data(), payload.size()), 0);
}

TEST(BuildUdpDatagram, ChecksumValidatesOverPseudoHeader) {
    // Re-run the RFC 1071 sum over the pseudo-header + UDP region the
    // receiver reconstructs. A conformant builder produces a datagram
    // whose one's-complement sum collapses to 0xFFFF (the "all-ones"
    // form of zero). ADDRESSING_01/02 and FRAGMENTS_05 all rely on the
    // DUT's kernel accepting these datagrams — a silent checksum bug
    // would false-pass the tests against tc8-dut-drop-on-bad-csum.
    const std::array<std::uint8_t, 8> payload{1, 2, 3, 4, 5, 6, 7, 8};
    const auto d = buildUdpDatagram(kTesterIpBe, kDutIpBe, 20001, 20000,
                                    payload.data(), payload.size());
    ASSERT_EQ(d.size(), 8u + payload.size());

    std::vector<std::uint8_t> region;
    region.reserve(12U + d.size());
    for (int i = 0; i < 4; ++i) {
        region.push_back(static_cast<std::uint8_t>((kTesterIpBe >> (i * 8)) & 0xFFU));
    }
    for (int i = 0; i < 4; ++i) {
        region.push_back(static_cast<std::uint8_t>((kDutIpBe >> (i * 8)) & 0xFFU));
    }
    region.push_back(0x00U);
    region.push_back(0x11U);
    region.push_back(0x00U);
    region.push_back(static_cast<std::uint8_t>(d.size()));
    region.insert(region.end(), d.begin(), d.end());
    EXPECT_EQ(runningSumRef(region.data(), region.size()), 0xFFFFU);
}

TEST(BuildUdpDatagram, ZeroPayloadChecksumIsNonZero) {
    // RFC 768 §Format: when the computed sum is 0x0000, transmit
    // 0xFFFF to avoid the "checksum not computed" wire sentinel. Any
    // non-trivial (src_ip, dst_ip, ports) produces a non-zero compute,
    // but pin the sentinel-guard here so a future refactor doesn't
    // silently drop it.
    const auto d = buildUdpDatagram(kTesterIpBe, kDutIpBe, 0, 0, nullptr, 0);
    ASSERT_EQ(d.size(), 8u);
    const std::uint16_t csum =
        static_cast<std::uint16_t>((d[6] << 8) | d[7]);
    EXPECT_NE(csum, 0x0000U);
}

// §4.6.5.4 UDP_FIELDS_09: Length=0 override post-compute. The wire
// retains 8 B header + payload but bytes [4..5] read 0x0000 — Linux
// drops on `length < 8` decode.
TEST(BuildUdpDatagramWithOverrides, LengthFieldOverrideRewritesBytes) {
    const std::array<std::uint8_t, 4> payload{0xAA, 0xBB, 0xCC, 0xDD};
    UdpDatagramOverrides ov{};
    ov.length_field = std::uint16_t{0x0000};
    const auto d = buildUdpDatagramWithOverrides(
        kTesterIpBe, kDutIpBe, 1, 2, payload.data(), payload.size(), ov);
    ASSERT_EQ(d.size(), 8u + payload.size());
    EXPECT_EQ(d[4], 0x00U);
    EXPECT_EQ(d[5], 0x00U);
    EXPECT_EQ(std::memcmp(d.data() + 8, payload.data(), payload.size()), 0);
}

// §4.6.5.4 UDP_FIELDS_15: Checksum override post-compute. The wire
// keeps the conformant length, only the 2-byte checksum slot diverges.
TEST(BuildUdpDatagramWithOverrides, ChecksumFieldOverrideWritesRaw) {
    UdpDatagramOverrides ov{};
    ov.checksum_field = std::uint16_t{0xDEAD};
    const auto d = buildUdpDatagramWithOverrides(
        kTesterIpBe, kDutIpBe, 1, 2, nullptr, 0, ov);
    ASSERT_EQ(d.size(), 8u);
    EXPECT_EQ(d[6], 0xDEU);
    EXPECT_EQ(d[7], 0xADU);
}

// §4.6.5.4 UDP_FIELDS_16: zero-checksum sentinel. The override path
// writes the literal 0x0000 even though the conformant compute would
// produce non-zero — caller-signalled "checksum not computed".
TEST(BuildUdpDatagramWithOverrides, ZeroChecksumOverrideKeepsLiteralZero) {
    const std::array<std::uint8_t, 2> payload{0x12, 0x34};
    UdpDatagramOverrides ov{};
    ov.checksum_field = std::uint16_t{0x0000};
    const auto d = buildUdpDatagramWithOverrides(
        kTesterIpBe, kDutIpBe, 1, 2, payload.data(), payload.size(), ov);
    ASSERT_EQ(d.size(), 8u + payload.size());
    EXPECT_EQ(d[6], 0x00U);
    EXPECT_EQ(d[7], 0x00U);
}

// §4.6.5.4 UDP_FIELDS_08: truncate to sub-8-byte UDP region. The
// returned vector is exactly `truncate_to` bytes — Linux's UDP
// decoder rejects on `frame_remaining < 8`.
TEST(BuildUdpDatagramWithOverrides, TruncateToSubHeaderShrinksRegion) {
    UdpDatagramOverrides ov{};
    ov.truncate_to = std::size_t{4};
    const auto d = buildUdpDatagramWithOverrides(
        kTesterIpBe, kDutIpBe, 0x1234, 0xABCD, nullptr, 0, ov);
    ASSERT_EQ(d.size(), 4u);
    // Source/destination port bytes survive — the surviving prefix
    // should match the leading 4 B of a normal datagram.
    EXPECT_EQ(d[0], 0x12U);
    EXPECT_EQ(d[1], 0x34U);
    EXPECT_EQ(d[2], 0xABU);
    EXPECT_EQ(d[3], 0xCDU);
}

// Truncate >= 8 is a no-op — the override only shrinks; growth would
// need a different stimulus (raw IP payload extension).
TEST(BuildUdpDatagramWithOverrides, TruncateAtOrAboveHeaderIsNoOp) {
    UdpDatagramOverrides ov{};
    ov.truncate_to = std::size_t{8};
    const auto d = buildUdpDatagramWithOverrides(
        kTesterIpBe, kDutIpBe, 1, 2, nullptr, 0, ov);
    EXPECT_EQ(d.size(), 8u);
}

}  // namespace
}  // namespace tc8::stimulus
