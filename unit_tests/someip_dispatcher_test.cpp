// Pins SOME/IP datagram-grouping in SomeIpDispatcher. A single UDP datagram
// MAY carry several concatenated SOME/IP messages (PRS_SOMEIP); deliver()
// stamps each emitted event with its 0-based position within the datagram
// (`datagram_msg_index`) and the datagram's total message count
// (`datagram_msg_count`), so a case can assert the DUT packed N messages into
// one datagram (PRS_SOMEIP permits message concatenation). The TCP
// stream path (feed()) has no datagram boundary and must leave the count-0
// sentinel rather than claim a spurious "sole message" (count 1).

#include <gtest/gtest.h>

#include <cstdint>
#include <variant>
#include <vector>

#include "dissect/someip_dispatcher.h"
#include "dissect/transport.h"
#include "tc8/captured_event.h"
#include "tc8/protocol_frames/someip_frame.h"

namespace {

void appendBe16(std::vector<std::uint8_t> &b, std::uint16_t v) {
    b.push_back(static_cast<std::uint8_t>((v >> 8) & 0xFF));
    b.push_back(static_cast<std::uint8_t>(v & 0xFF));
}

void appendBe32(std::vector<std::uint8_t> &b, std::uint32_t v) {
    b.push_back(static_cast<std::uint8_t>((v >> 24) & 0xFF));
    b.push_back(static_cast<std::uint8_t>((v >> 16) & 0xFF));
    b.push_back(static_cast<std::uint8_t>((v >> 8) & 0xFF));
    b.push_back(static_cast<std::uint8_t>(v & 0xFF));
}

// Append one complete SOME/IP message: the 16-byte header (Length covers the
// 8 post-Length header bytes + payload) then `payload_len` filler bytes. The
// dispatcher does not validate Message Type / versions, so the chosen values
// are arbitrary-but-valid.
void appendMsg(std::vector<std::uint8_t> &b, std::uint16_t service, std::uint16_t method,
               std::uint32_t payload_len) {
    appendBe16(b, service);            // Service ID
    appendBe16(b, method);             // Method ID
    appendBe32(b, 8u + payload_len);   // Length
    appendBe16(b, 0x0000);             // Client ID
    appendBe16(b, 0x0001);             // Session ID
    b.push_back(0x01);                 // Protocol Version
    b.push_back(0x01);                 // Interface Version
    b.push_back(0x02);                 // Message Type (NOTIFICATION)
    b.push_back(0x00);                 // Return Code
    for (std::uint32_t i = 0; i < payload_len; ++i) {
        b.push_back(static_cast<std::uint8_t>(0xA0 + (i & 0x0F)));
    }
}

tc8::dissect::Transport udpTransport() {
    tc8::dissect::Transport t{};
    t.proto = tc8::dissect::Transport::Proto::Udp;
    t.src_ip = 0x0A000001;
    t.dst_ip = 0x0A0000FF;
    t.src_port = 30509;
    t.dst_port = 30490;
    return t;
}

std::vector<tc8::SomeIpFrame> dispatchUdp(const std::vector<std::uint8_t> &buf) {
    tc8::dissect::SomeIpDispatcher d;
    std::vector<tc8::SomeIpFrame> out;
    d.deliver(udpTransport(), buf.data(), buf.size(), [&](const tc8::CapturedEvent &ev) {
        if (const auto *f = std::get_if<tc8::SomeIpFrame>(&ev)) {
            out.push_back(*f);
        }
    });
    return out;
}

}  // namespace

TEST(SomeIpDispatcherGrouping, MultipleMessagesPerDatagramStampIndexAndCount) {
    std::vector<std::uint8_t> buf;
    appendMsg(buf, 0x0053, 0x0001, 4);
    appendMsg(buf, 0x0054, 0x0001, 4);
    appendMsg(buf, 0x0055, 0x0001, 4);

    const auto events = dispatchUdp(buf);
    ASSERT_EQ(events.size(), 3u);

    // Wire order preserved.
    EXPECT_EQ(events[0].service_id, 0x0053);
    EXPECT_EQ(events[1].service_id, 0x0054);
    EXPECT_EQ(events[2].service_id, 0x0055);

    // Every message of the datagram reports the same count and its own index.
    for (std::uint16_t i = 0; i < 3; ++i) {
        EXPECT_EQ(events[i].datagram_msg_index, i);
        EXPECT_EQ(events[i].datagram_msg_count, 3u);
    }
}

TEST(SomeIpDispatcherGrouping, SoleMessageReportsCountOne) {
    std::vector<std::uint8_t> buf;
    appendMsg(buf, 0x0053, 0x0001, 0);  // header-only message

    const auto events = dispatchUdp(buf);
    ASSERT_EQ(events.size(), 1u);
    EXPECT_EQ(events[0].datagram_msg_index, 0u);
    EXPECT_EQ(events[0].datagram_msg_count, 1u);
}

TEST(SomeIpDispatcherGrouping, CountReflectsParseablePrefixOnly) {
    // Two valid messages followed by a tail too short to be a SOME/IP header.
    // deliver() stops at the bad tail, so the count reflects only the messages
    // it actually emitted (not an over-count from the trailing garbage).
    std::vector<std::uint8_t> buf;
    appendMsg(buf, 0x0053, 0x0001, 0);
    appendMsg(buf, 0x0054, 0x0001, 0);
    buf.push_back(0xFF);  // < 8 bytes left -> parseSomeIpHeader fails

    const auto events = dispatchUdp(buf);
    ASSERT_EQ(events.size(), 2u);
    EXPECT_EQ(events[0].datagram_msg_count, 2u);
    EXPECT_EQ(events[1].datagram_msg_count, 2u);
    EXPECT_EQ(events[1].datagram_msg_index, 1u);
}

TEST(SomeIpDispatcherGrouping, EmptyDatagramEmitsNothing) {
    const auto events = dispatchUdp({});
    EXPECT_TRUE(events.empty());
}

TEST(SomeIpDispatcherGrouping, TcpFeedLeavesCountSentinelZero) {
    // The TCP stream path has no datagram boundary, so it must not claim a
    // message is the sole member of a datagram (count 1) — it leaves the
    // count-0 sentinel. A single complete message fed as one segment.
    std::vector<std::uint8_t> buf;
    appendMsg(buf, 0x0053, 0x0001, 4);

    tc8::dissect::SomeIpDispatcher d;
    tc8::dissect::Transport t = udpTransport();
    t.proto = tc8::dissect::Transport::Proto::Tcp;

    std::vector<tc8::SomeIpFrame> out;
    d.feed(t, buf.data(), buf.size(), [&](const tc8::CapturedEvent &ev) {
        if (const auto *f = std::get_if<tc8::SomeIpFrame>(&ev)) {
            out.push_back(*f);
        }
    });

    ASSERT_EQ(out.size(), 1u);
    EXPECT_EQ(out[0].service_id, 0x0053);
    EXPECT_EQ(out[0].datagram_msg_count, 0u);
}
