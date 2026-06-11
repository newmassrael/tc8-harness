#include <array>
#include <cstdint>
#include <vector>

#include <gtest/gtest.h>

#include "sce_integration/tcp_captured.h"
#include "tc8/protocol_frames/tcp_frame.h"

// Coverage for TcpCaptured::is_zero_window_probe — the §4.8.6.12
// PROBING_WINDOWS_04/05/06 matcher that accepts either RFC 1122
// §4.2.2.17-conformant zero-window probe shape (Linux's 0-byte
// garbage-octet at snd_una-1, or the BSD/lwIP 1-byte new-data probe at
// snd_una) while rejecting the handshake third-leg ACK and genuine
// data segments. expected_ack_num is the stimulus-preloaded snd_una-1.

namespace tc8 {
namespace {

constexpr std::uint32_t kDutIp     = 0x0200A8C0;  // 192.168.0.2 NBO
constexpr std::uint32_t kTesterIp  = 0x0100A8C0;  // 192.168.0.1 NBO
constexpr std::uint16_t kDutPort   = 49500;       // DUT active-OPEN local
constexpr std::uint16_t kTestPort  = 23456;       // tester remote
constexpr std::uint32_t kSndUna    = 0x10203050;  // snd_una post window-0 ACK
constexpr std::uint32_t kExpected  = kSndUna - 1U;  // preloaded expected_ack_num
constexpr std::uint8_t  kAck = 0x10, kSyn = 0x02, kRst = 0x04, kFin = 0x01;

// A DUT-origin pure ACK on the case 4-tuple — the common base from
// which each test perturbs one field.
TcpCaptured baseProbe() {
    TcpCaptured c{};
    c.src_ip = kDutIp;
    c.dst_ip = kTesterIp;
    c.src_port = kDutPort;
    c.dst_port = kTestPort;
    c.flags = kAck;
    c.expected_ack_num = kExpected;
    return c;
}

bool match(const TcpCaptured& c) {
    return c.is_zero_window_probe(kDutIp, kTesterIp, kDutPort, kTestPort);
}

TEST(TcpZeroWindowProbe, AcceptsLinuxGarbageOctet) {
    // 0-byte ACK at snd_una - 1.
    TcpCaptured c = baseProbe();
    c.payload_len = 0U;
    c.seq_num = kExpected;
    EXPECT_TRUE(match(c));
}

TEST(TcpZeroWindowProbe, AcceptsBsdOneNewByte) {
    // 1-byte new-data segment at snd_una (= expected_ack_num + 1).
    TcpCaptured c = baseProbe();
    c.payload_len = 1U;
    c.seq_num = kExpected + 1U;
    EXPECT_TRUE(match(c));
}

TEST(TcpZeroWindowProbe, RejectsHandshakeThirdLegAck) {
    // A pure ACK whose seq is neither snd_una-1 nor snd_una (e.g. the
    // handshake ACK at seg1_seq) must not satisfy the probe guard.
    TcpCaptured c = baseProbe();
    c.payload_len = 0U;
    c.seq_num = kExpected - 100U;
    EXPECT_FALSE(match(c));
}

TEST(TcpZeroWindowProbe, RejectsZeroByteAtSndUna) {
    // 0-byte segment at snd_una (not snd_una-1) is not the Linux shape.
    TcpCaptured c = baseProbe();
    c.payload_len = 0U;
    c.seq_num = kExpected + 1U;
    EXPECT_FALSE(match(c));
}

TEST(TcpZeroWindowProbe, RejectsGenuineDataSegment) {
    // A >1-byte data segment at snd_una is a real send, not a probe.
    TcpCaptured c = baseProbe();
    c.payload_len = 8U;
    c.seq_num = kExpected + 1U;
    EXPECT_FALSE(match(c));
}

TEST(TcpZeroWindowProbe, RejectsOneByteAtSndUnaMinusOne) {
    // 1-byte payload must sit at snd_una, not snd_una-1.
    TcpCaptured c = baseProbe();
    c.payload_len = 1U;
    c.seq_num = kExpected;
    EXPECT_FALSE(match(c));
}

TEST(TcpZeroWindowProbe, RejectsWrongFourTuple) {
    TcpCaptured c = baseProbe();
    c.payload_len = 1U;
    c.seq_num = kExpected + 1U;
    c.src_ip = 0x6363630A;  // 10.99.99.99 — negative-flip address
    EXPECT_FALSE(match(c));
}

TEST(TcpZeroWindowProbe, RejectsControlFlags) {
    // SYN / FIN / RST set alongside ACK disqualifies a probe.
    for (std::uint8_t bad : {kSyn, kFin, kRst}) {
        TcpCaptured c = baseProbe();
        c.payload_len = 1U;
        c.seq_num = kExpected + 1U;
        c.flags = static_cast<std::uint8_t>(kAck | bad);
        EXPECT_FALSE(match(c)) << "flags=" << static_cast<int>(c.flags);
    }
}

TEST(TcpZeroWindowProbe, RejectsAckBitClear) {
    TcpCaptured c = baseProbe();
    c.payload_len = 1U;
    c.seq_num = kExpected + 1U;
    c.flags = 0U;  // ACK clear
    EXPECT_FALSE(match(c));
}

// Coverage for the §D3 TcpCaptured payload snapshot — the symmetric
// surface to UdpCaptured::payload_snapshot that lets an SCXML cond
// verify an application-layer protocol carried over TCP byte-for-byte.

TcpFrame frameWithPayload(const std::uint8_t *payload,
                          std::uint32_t        payload_len) {
    TcpFrame f{};
    f.src_ip       = kDutIp;
    f.dst_ip       = kTesterIp;
    f.src_port     = kDutPort;
    f.dst_port     = kTestPort;
    f.flags        = kAck;
    f.payload_data = payload;
    f.payload_len  = payload_len;
    return f;
}

TEST(TcpPayloadSnapshot, CopiesLeadingBytesAndLength) {
    const std::array<std::uint8_t, 6> body{0x02, 0xFD, 0x80, 0x01, 0x00, 0x00};
    const auto f = frameWithPayload(body.data(),
                                    static_cast<std::uint32_t>(body.size()));
    TcpCaptured c{};
    fillTcpCapturedFromFrame(c, f);
    EXPECT_EQ(c.payload_len, 6U);
    EXPECT_EQ(c.payload_snapshot_len, 6U);
    for (std::size_t i = 0; i < body.size(); ++i) {
        EXPECT_EQ(c.payload_snapshot[i], body[i]) << "i=" << i;
    }
}

TEST(TcpPayloadSnapshot, EmptyPayloadLeavesSnapshotZeroed) {
    const auto f = frameWithPayload(nullptr, 0);
    TcpCaptured c{};
    fillTcpCapturedFromFrame(c, f);
    EXPECT_EQ(c.payload_snapshot_len, 0U);
    for (const auto b : c.payload_snapshot) EXPECT_EQ(b, 0U);
}

TEST(TcpPayloadSnapshot, OversizedPayloadCappedAtSnapshotSize) {
    // A segment payload larger than the snapshot is captured up to the
    // cap; payload_snapshot_len records the truncated count while
    // payload_len keeps the full wire length.
    std::vector<std::uint8_t> big(TcpCaptured::kMaxPayloadSnapshot + 32, 0xAB);
    for (std::size_t i = 0; i < big.size(); ++i) {
        big[i] = static_cast<std::uint8_t>(i & 0xFFU);
    }
    const auto f = frameWithPayload(big.data(),
                                    static_cast<std::uint32_t>(big.size()));
    TcpCaptured c{};
    fillTcpCapturedFromFrame(c, f);
    EXPECT_EQ(c.payload_len, big.size());
    EXPECT_EQ(c.payload_snapshot_len, TcpCaptured::kMaxPayloadSnapshot);
    for (std::size_t i = 0; i < TcpCaptured::kMaxPayloadSnapshot; ++i) {
        EXPECT_EQ(c.payload_snapshot[i], static_cast<std::uint8_t>(i & 0xFFU))
            << "i=" << i;
    }
}

TEST(TcpPayloadBytesEq, MatchingPrefixAccepted) {
    const std::array<std::uint8_t, 5> body{0x02, 0xFD, 0x80, 0x01, 0xCC};
    const auto f = frameWithPayload(body.data(),
                                    static_cast<std::uint32_t>(body.size()));
    TcpCaptured c{};
    fillTcpCapturedFromFrame(c, f);
    EXPECT_TRUE(c.payload_bytes_eq({0x02, 0xFD, 0x80, 0x01}));
    EXPECT_TRUE(c.payload_bytes_eq({0x02, 0xFD, 0x80, 0x01, 0xCC}));
}

TEST(TcpPayloadBytesEq, MismatchedByteRejected) {
    const std::array<std::uint8_t, 4> body{0x02, 0xFD, 0x80, 0x01};
    const auto f = frameWithPayload(body.data(),
                                    static_cast<std::uint32_t>(body.size()));
    TcpCaptured c{};
    fillTcpCapturedFromFrame(c, f);
    EXPECT_FALSE(c.payload_bytes_eq({0x02, 0xFD, 0x80, 0x02}));
}

TEST(TcpPayloadBytesEq, AssertionLongerThanCapturedRejected) {
    // Truncation guard: asserting more bytes than were captured must
    // fail rather than read past payload_snapshot_len.
    const std::array<std::uint8_t, 3> body{0x02, 0xFD, 0x80};
    const auto f = frameWithPayload(body.data(),
                                    static_cast<std::uint32_t>(body.size()));
    TcpCaptured c{};
    fillTcpCapturedFromFrame(c, f);
    EXPECT_FALSE(c.payload_bytes_eq({0x02, 0xFD, 0x80, 0x01}));
}

TEST(TcpPayloadBytesEq, EmptyExpectationMatchesAnyCapture) {
    const std::array<std::uint8_t, 2> body{0x02, 0xFD};
    const auto f = frameWithPayload(body.data(),
                                    static_cast<std::uint32_t>(body.size()));
    TcpCaptured c{};
    fillTcpCapturedFromFrame(c, f);
    EXPECT_TRUE(c.payload_bytes_eq({}));
}

}  // namespace
}  // namespace tc8
