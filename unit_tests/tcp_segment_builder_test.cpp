#include <array>
#include <cstdint>
#include <cstring>
#include <vector>

#include <gtest/gtest.h>

#include "stimulus/tcp_segment_builder.h"

namespace tc8::stimulus {
namespace {

constexpr std::uint32_t kTesterIpBe = 0x010010AC;  // 172.16.0.1
constexpr std::uint32_t kDutIpBe    = 0x020010AC;  // 172.16.0.2

// Reference one's-complement running sum matching RFC 1071. The builder
// produces a segment whose pseudo-header + TCP region sum collapses to
// 0xFFFF (all-ones form of zero) — the validity invariant the DUT's
// kernel applies on receive.
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

TEST(BuildTcpSegment, HeaderOnlyIs20Bytes) {
    TcpSegmentSpec spec{};
    spec.src_port = 12345;
    spec.dst_port = 80;
    spec.flags    = kTcpFlagSyn;
    const auto s = buildTcpSegment(kTesterIpBe, kDutIpBe, spec);
    EXPECT_EQ(s.size(), 20u);
}

TEST(BuildTcpSegment, PortsAndSeqAckAreBigEndian) {
    TcpSegmentSpec spec{};
    spec.src_port = 0x1234;
    spec.dst_port = 0xABCD;
    spec.seq_num  = 0x11223344U;
    spec.ack_num  = 0xAABBCCDDU;
    spec.flags    = kTcpFlagAck;
    const auto s = buildTcpSegment(kTesterIpBe, kDutIpBe, spec);
    ASSERT_GE(s.size(), 20u);
    EXPECT_EQ(s[0], 0x12U);
    EXPECT_EQ(s[1], 0x34U);
    EXPECT_EQ(s[2], 0xABU);
    EXPECT_EQ(s[3], 0xCDU);
    EXPECT_EQ(s[4], 0x11U);
    EXPECT_EQ(s[5], 0x22U);
    EXPECT_EQ(s[6], 0x33U);
    EXPECT_EQ(s[7], 0x44U);
    EXPECT_EQ(s[8], 0xAAU);
    EXPECT_EQ(s[9], 0xBBU);
    EXPECT_EQ(s[10], 0xCCU);
    EXPECT_EQ(s[11], 0xDDU);
}

TEST(BuildTcpSegment, DataOffsetReflectsOptionsLength) {
    // 4 B option (MSS) → Data Offset = (20 + 4) / 4 = 6.
    TcpSegmentSpec spec{};
    spec.src_port = 1;
    spec.dst_port = 2;
    spec.flags    = kTcpFlagSyn;
    spec.options  = {0x02, 0x04, 0x05, 0xB4};  // MSS = 1460
    const auto s = buildTcpSegment(kTesterIpBe, kDutIpBe, spec);
    ASSERT_GE(s.size(), 24u);
    EXPECT_EQ(s[12] >> 4, 6u);
}

TEST(BuildTcpSegment, OptionsPaddedWithNop) {
    // 3 B option triggers one NOP of padding to reach 4-byte alignment.
    // Data Offset stays 6; the padded region is 4 B (3 option + 1 NOP).
    TcpSegmentSpec spec{};
    spec.flags   = kTcpFlagSyn;
    spec.options = {0xAA, 0xBB, 0xCC};
    const auto s = buildTcpSegment(kTesterIpBe, kDutIpBe, spec);
    ASSERT_GE(s.size(), 24u);
    EXPECT_EQ(s[12] >> 4, 6u);
    EXPECT_EQ(s[20], 0xAAU);
    EXPECT_EQ(s[21], 0xBBU);
    EXPECT_EQ(s[22], 0xCCU);
    EXPECT_EQ(s[23], 0x01U);  // NOP
}

TEST(BuildTcpSegment, FlagsByteCarriesAllSetBits) {
    TcpSegmentSpec spec{};
    spec.flags = static_cast<std::uint8_t>(
        kTcpFlagSyn | kTcpFlagAck | kTcpFlagPsh);
    const auto s = buildTcpSegment(kTesterIpBe, kDutIpBe, spec);
    ASSERT_GE(s.size(), 20u);
    EXPECT_EQ(s[13],
              static_cast<std::uint8_t>(kTcpFlagSyn | kTcpFlagAck | kTcpFlagPsh));
}

TEST(BuildTcpSegment, PayloadAppendsAfterHeaderAndOptions) {
    const std::array<std::uint8_t, 5> payload{0xDE, 0xAD, 0xBE, 0xEF, 0x99};
    TcpSegmentSpec spec{};
    spec.flags   = kTcpFlagPsh | kTcpFlagAck;
    spec.payload.assign(payload.begin(), payload.end());
    const auto s = buildTcpSegment(kTesterIpBe, kDutIpBe, spec);
    ASSERT_EQ(s.size(), 20u + payload.size());
    EXPECT_EQ(std::memcmp(s.data() + 20, payload.data(), payload.size()), 0);
}

TEST(BuildTcpSegment, ChecksumValidatesOverPseudoHeader) {
    // RFC 793 §3.1: pseudo-header + header + payload sums to 0xFFFF.
    // §4.8.6.1 TCP_BASICS rely on the DUT's kernel accepting these
    // segments — a silent checksum bug would false-pass against a
    // drop-on-bad-csum DUT.
    TcpSegmentSpec spec{};
    spec.src_port = 49152;
    spec.dst_port = 12345;
    spec.seq_num  = 0x01020304U;
    spec.flags    = kTcpFlagSyn;
    const auto s = buildTcpSegment(kTesterIpBe, kDutIpBe, spec);
    ASSERT_EQ(s.size(), 20u);

    std::vector<std::uint8_t> region;
    region.reserve(12U + s.size());
    for (int i = 0; i < 4; ++i) {
        region.push_back(
            static_cast<std::uint8_t>((kTesterIpBe >> (i * 8)) & 0xFFU));
    }
    for (int i = 0; i < 4; ++i) {
        region.push_back(
            static_cast<std::uint8_t>((kDutIpBe >> (i * 8)) & 0xFFU));
    }
    region.push_back(0x00U);
    region.push_back(0x06U);  // TCP
    region.push_back(0x00U);
    region.push_back(static_cast<std::uint8_t>(s.size()));
    region.insert(region.end(), s.begin(), s.end());
    EXPECT_EQ(runningSumRef(region.data(), region.size()), 0xFFFFU);
}

TEST(BuildTcpSegment, ChecksumValidatesWithPayload) {
    const std::array<std::uint8_t, 7> payload{1, 2, 3, 4, 5, 6, 7};
    TcpSegmentSpec spec{};
    spec.src_port = 20100;
    spec.dst_port = 12345;
    spec.seq_num  = 0xDEADBEEFU;
    spec.ack_num  = 0x12345678U;
    spec.flags    = kTcpFlagPsh | kTcpFlagAck;
    spec.payload.assign(payload.begin(), payload.end());
    const auto s = buildTcpSegment(kTesterIpBe, kDutIpBe, spec);
    ASSERT_EQ(s.size(), 20u + payload.size());

    std::vector<std::uint8_t> region;
    region.reserve(12U + s.size());
    for (int i = 0; i < 4; ++i) {
        region.push_back(
            static_cast<std::uint8_t>((kTesterIpBe >> (i * 8)) & 0xFFU));
    }
    for (int i = 0; i < 4; ++i) {
        region.push_back(
            static_cast<std::uint8_t>((kDutIpBe >> (i * 8)) & 0xFFU));
    }
    region.push_back(0x00U);
    region.push_back(0x06U);
    region.push_back(0x00U);
    region.push_back(static_cast<std::uint8_t>(s.size()));
    region.insert(region.end(), s.begin(), s.end());
    EXPECT_EQ(runningSumRef(region.data(), region.size()), 0xFFFFU);
}

TEST(BuildTcpSegment, CorruptChecksumPerturbsValidSum) {
    // §4.8.6.2 CHECKSUM_02 stimulus pin. With corrupt=false the pseudo-
    // header + segment region sums to 0xFFFF (RFC 1071 valid form);
    // with corrupt=true the same region sums to anything other than
    // 0xFFFF. Verifying both arms in one test guards against a future
    // refactor that disables the flag silently — a one-bit XOR is
    // structurally the smallest perturbation that breaks validity.
    TcpSegmentSpec spec{};
    spec.src_port = 49152;
    spec.dst_port = 12345;
    spec.seq_num  = 0x01020304U;
    spec.flags    = kTcpFlagPsh | kTcpFlagAck;
    spec.payload  = {0xAA, 0xBB, 0xCC, 0xDD};

    auto buildAndSum = [&](bool corrupt) {
        spec.corrupt_tcp_checksum = corrupt;
        const auto s = buildTcpSegment(kTesterIpBe, kDutIpBe, spec);
        std::vector<std::uint8_t> region;
        region.reserve(12U + s.size());
        for (int i = 0; i < 4; ++i) {
            region.push_back(
                static_cast<std::uint8_t>((kTesterIpBe >> (i * 8)) & 0xFFU));
        }
        for (int i = 0; i < 4; ++i) {
            region.push_back(
                static_cast<std::uint8_t>((kDutIpBe >> (i * 8)) & 0xFFU));
        }
        region.push_back(0x00U);
        region.push_back(0x06U);
        region.push_back(0x00U);
        region.push_back(static_cast<std::uint8_t>(s.size()));
        region.insert(region.end(), s.begin(), s.end());
        return runningSumRef(region.data(), region.size());
    };

    EXPECT_EQ(buildAndSum(false), 0xFFFFU);
    EXPECT_NE(buildAndSum(true),  0xFFFFU);
}

TEST(BuildTcpSegment, ReservedOverrideEncodesLowNibble) {
    // §4.8.6.X TCP_HEADER_06: reserved=0xF must land in byte[12] low
    // nibble while the data_offset (high nibble) stays untouched. The
    // mask guards against accidental width promotion (e.g., a future
    // refactor to uint16_t) silently overwriting data_offset.
    TcpSegmentSpec spec{};
    spec.flags             = kTcpFlagAck;
    spec.reserved_override = 0x0FU;
    const auto s = buildTcpSegment(kTesterIpBe, kDutIpBe, spec);
    ASSERT_GE(s.size(), 20u);
    EXPECT_EQ(s[12] >> 4, 5u);            // data_offset still 5
    EXPECT_EQ(s[12] & 0x0FU, 0x0FU);      // reserved nibble = 0xF
}

TEST(BuildTcpSegment, DataOffsetOverrideReplacesAutoComputed) {
    // §4.8.6.X TCP_HEADER_07: data_offset < 5 drives Linux's
    // tcp_v4_rcv bad_packet path. §4.8.6.X TCP_HEADER_08: data_offset
    // > actual segment length drives pskb_may_pull discard. Both
    // override only byte[12] high nibble; the encoded segment bytes
    // stay 20 + payload, isolating the spec-asserted discard reason.
    TcpSegmentSpec spec_low{};
    spec_low.flags                = kTcpFlagAck;
    spec_low.data_offset_override = 0x04U;
    const auto s_low = buildTcpSegment(kTesterIpBe, kDutIpBe, spec_low);
    ASSERT_GE(s_low.size(), 20u);
    EXPECT_EQ(s_low[12] >> 4, 0x04U);
    EXPECT_EQ(s_low.size(), 20u);          // wire bytes unchanged

    TcpSegmentSpec spec_high{};
    spec_high.flags                = kTcpFlagAck;
    spec_high.data_offset_override = 0x0FU;
    const auto s_high = buildTcpSegment(kTesterIpBe, kDutIpBe, spec_high);
    ASSERT_GE(s_high.size(), 20u);
    EXPECT_EQ(s_high[12] >> 4, 0x0FU);
    EXPECT_EQ(s_high.size(), 20u);
}

TEST(BuildTcpSegment, ForceZeroChecksumPlacesAbsoluteZero) {
    // §4.8.6.X TCP_HEADER_09 spec literal "Checksum = 0". The
    // checksum field bytes [16..17] must be exactly 0x00 0x00,
    // regardless of what the pseudo-header sum would have produced.
    // Pin both arms to guard against a refactor that conflates this
    // with corrupt_tcp_checksum (XOR 0x0001 perturbation).
    TcpSegmentSpec spec{};
    spec.src_port               = 49152;
    spec.dst_port               = 12345;
    spec.seq_num                = 0x01020304U;
    spec.flags                  = kTcpFlagPsh | kTcpFlagAck;
    spec.payload                = {0xAA, 0xBB, 0xCC, 0xDD};
    spec.force_zero_tcp_checksum = true;
    const auto s = buildTcpSegment(kTesterIpBe, kDutIpBe, spec);
    ASSERT_GE(s.size(), 20u);
    EXPECT_EQ(s[16], 0x00U);
    EXPECT_EQ(s[17], 0x00U);
}

TEST(BuildTcpSegment, FlagLiteralsAreRfc793Bits) {
    // Pin the literal values so a future refactor can't silently swap
    // SYN/FIN/RST bit positions. RFC 793 §3.1 Control Bits byte-13
    // layout: URG ACK PSH RST SYN FIN (bits 5..0).
    EXPECT_EQ(kTcpFlagFin, 0x01U);
    EXPECT_EQ(kTcpFlagSyn, 0x02U);
    EXPECT_EQ(kTcpFlagRst, 0x04U);
    EXPECT_EQ(kTcpFlagPsh, 0x08U);
    EXPECT_EQ(kTcpFlagAck, 0x10U);
    EXPECT_EQ(kTcpFlagUrg, 0x20U);
}

}  // namespace
}  // namespace tc8::stimulus
