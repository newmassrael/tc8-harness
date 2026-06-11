#include <cstdint>

#include <gtest/gtest.h>

#include "sce_integration/tcp_captured.h"

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

}  // namespace
}  // namespace tc8
