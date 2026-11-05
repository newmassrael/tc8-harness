// The harness's own wire decoders (tc8/wire/, docs/tech-debt.md TD-69): each reads every
// input its standard allows, records deviations instead of refusing them, and answers
// "nothing" only where a header cannot be located.
#include <cstdint>
#include <cstring>
#include <vector>

#include <gtest/gtest.h>

#include "tc8/wire/arp_packet.h"
#include "tc8/wire/ethernet_frame.h"
#include "tc8/wire/icmpv4_message.h"
#include "tc8/wire/tcp_segment.h"
#include "tc8/wire/udp_datagram.h"

namespace {

using namespace ::tc8::wire;

std::vector<std::uint8_t> ethernet(std::uint16_t type, const std::vector<std::uint8_t> &rest) {
    std::vector<std::uint8_t> f = {0x02, 0, 0, 0, 0, 0x01, 0x02, 0, 0, 0, 0, 0x02,
                                   static_cast<std::uint8_t>(type >> 8), static_cast<std::uint8_t>(type)};
    f.insert(f.end(), rest.begin(), rest.end());
    return f;
}

TEST(EthernetDecode, ReadsTheAddressesAndType) {
    const auto f = ethernet(0x0800, {0xAA});
    const auto e = decodeEthernet(f.data(), f.size());
    ASSERT_TRUE(e.has_value());
    EXPECT_EQ(e->ether_type, 0x0800);
    EXPECT_EQ(e->src[5], 0x02);
    EXPECT_FALSE(e->dot1q.has_value());
    EXPECT_EQ(e->payload_len, 1u);
}

TEST(EthernetDecode, ReadsOneDot1QTagAndTheTypeBehindIt) {
    // TCI: PCP 5, DEI 1, VID 100; then ARP.
    const auto f = ethernet(0x8100, {0xB0, 0x64, 0x08, 0x06, 0xAA});
    const auto e = decodeEthernet(f.data(), f.size());
    ASSERT_TRUE(e.has_value());
    ASSERT_TRUE(e->dot1q.has_value());
    EXPECT_EQ(e->dot1q->pcp, 5);
    EXPECT_TRUE(e->dot1q->dei);
    EXPECT_EQ(e->dot1q->vid, 100);
    EXPECT_EQ(e->ether_type, 0x0806);
    EXPECT_EQ(e->payload_len, 1u);
}

TEST(EthernetDecode, AFrameShorterThanItsHeaderOrTagIsNothing) {
    const auto f = ethernet(0x0800, {});
    EXPECT_FALSE(decodeEthernet(f.data(), 13).has_value());
    const auto tagged = ethernet(0x8100, {0x00, 0x01});
    EXPECT_FALSE(decodeEthernet(tagged.data(), tagged.size()).has_value());
}

TEST(ArpDecode, ReadsAnEthernetIpv4Packet) {
    const std::vector<std::uint8_t> p = {0x00, 0x01, 0x08, 0x00, 6, 4, 0x00, 0x02,
                                         1, 2, 3, 4, 5, 6, 192, 168, 0, 1,
                                         7, 8, 9, 10, 11, 12, 192, 168, 0, 2};
    const auto a = decodeArp(p.data(), p.size());
    ASSERT_TRUE(a.has_value());
    EXPECT_EQ(a->opcode, 2);
    EXPECT_EQ(a->sender_hw[0], 1);
    EXPECT_EQ(a->target_hw[5], 12);
    const std::uint8_t spa[4] = {192, 168, 0, 1};
    std::uint32_t spa_be = 0;
    std::memcpy(&spa_be, spa, 4);
    EXPECT_EQ(a->sender_proto_be, spa_be);
}

// A DUT whose only fault is a wrong length field sends the 28-byte layout with that byte
// changed: the packet is read at the Ethernet/IPv4 offsets and the field reported as it
// stands, so a case can grade it. Reading at the stated lengths would have lost it.
TEST(ArpDecode, AWrongLengthFieldIsReportedAndTheAddressesStillRead) {
    const std::vector<std::uint8_t> p = {0x00, 0x01, 0x08, 0x00, 8, 4, 0x00, 0x01,
                                         1, 2, 3, 4, 5, 6, 192, 168, 0, 1,
                                         0, 0, 0, 0, 0, 0, 192, 168, 0, 2};
    const auto a = decodeArp(p.data(), p.size());
    ASSERT_TRUE(a.has_value());
    EXPECT_EQ(a->hw_addr_len, 8);
    EXPECT_EQ(a->sender_hw[5], 6);
    const std::uint8_t tpa[4] = {192, 168, 0, 2};
    std::uint32_t tpa_be = 0;
    std::memcpy(&tpa_be, tpa, 4);
    EXPECT_EQ(a->target_proto_be, tpa_be);
    EXPECT_FALSE(decodeArp(p.data(), p.size() - 1).has_value());
}

TEST(Icmpv4Decode, ReadsAnEchoAndItsData) {
    const std::vector<std::uint8_t> p = {0x00, 0x00, 0x12, 0x34, 0xA7, 0xC8, 0x00, 0x05, 0xDE, 0xAD};
    const auto m = decodeIcmpv4(p.data(), p.size());
    ASSERT_TRUE(m.has_value());
    EXPECT_EQ(m->type, 0);
    EXPECT_EQ(m->checksum, 0x1234);
    EXPECT_EQ(m->rest_of_header, 0xA7C80005u);
    EXPECT_EQ(m->payload_len, 2u);
}

// RFC 792: the Timestamp messages carry three big-endian timestamps after the header.
TEST(Icmpv4Decode, ReadsTheThreeTimestamps) {
    const std::vector<std::uint8_t> p = {14, 0, 0, 0, 0, 1, 0, 1, 0x00, 0x00, 0x00, 0x0A,
                                         0x00, 0x00, 0x00, 0x0B, 0x00, 0x00, 0x00, 0x0C};
    const auto m = decodeIcmpv4(p.data(), p.size());
    ASSERT_TRUE(m.has_value());
    EXPECT_EQ(m->originate_timestamp, 10u);
    EXPECT_EQ(m->receive_timestamp, 11u);
    EXPECT_EQ(m->transmit_timestamp, 12u);
    EXPECT_EQ(m->payload, nullptr);
    EXPECT_FALSE(decodeIcmpv4(p.data(), 19).has_value());
}

// The Length field is reported, not used to cut the payload: a case judges a mismatch.
TEST(UdpDecode, KeepsALengthThatDisagreesWithWhatArrived) {
    const std::vector<std::uint8_t> p = {0x12, 0x34, 0x00, 0x35, 0x00, 0x04, 0x00, 0x00, 0xAA, 0xBB};
    const auto d = decodeUdp(p.data(), p.size());
    ASSERT_TRUE(d.has_value());
    EXPECT_EQ(d->length, 4);
    EXPECT_EQ(d->payload_len, 2u);
    const auto empty = decodeUdp(p.data(), 8);
    ASSERT_TRUE(empty.has_value());
    EXPECT_EQ(empty->payload, nullptr);
    EXPECT_FALSE(decodeUdp(p.data(), 7).has_value());
}

std::vector<std::uint8_t> tcpHeader(std::uint8_t data_offset, const std::vector<std::uint8_t> &options,
                                    const std::vector<std::uint8_t> &payload = {}) {
    std::vector<std::uint8_t> s = {0x30, 0x39, 0x00, 0x50, 0, 0, 0, 1, 0, 0, 0, 2,
                                   static_cast<std::uint8_t>(data_offset << 4), 0x12, 0xFF, 0xFF, 0, 0, 0, 0};
    s.insert(s.end(), options.begin(), options.end());
    s.insert(s.end(), payload.begin(), payload.end());
    return s;
}

TEST(TcpDecode, ReadsTheHeaderTheMssAndThePayload) {
    const auto s = tcpHeader(6, {0x02, 0x04, 0x05, 0xB4}, {0xAA});
    const auto t = decodeTcp(s.data(), s.size());
    ASSERT_TRUE(t.has_value());
    EXPECT_EQ(t->src_port, 12345);
    EXPECT_EQ(t->seq, 1u);
    EXPECT_EQ(t->ack, 2u);
    EXPECT_EQ(t->flags, 0x12);  // SYN | ACK
    ASSERT_TRUE(t->mss.has_value());
    EXPECT_EQ(*t->mss, 1460);
    EXPECT_EQ(t->payload_len, 1u);
    EXPECT_FALSE(t->options_malformed);
}

// RFC 793: End of Option List ends the list and the rest is padding.
TEST(TcpDecode, EndOfListFollowedByPaddingIsNormal) {
    const auto s = tcpHeader(7, {0x01, 0x00, 0x00, 0x00, 0x02, 0x04, 0x05, 0xB4});
    const auto t = decodeTcp(s.data(), s.size());
    ASSERT_TRUE(t.has_value());
    EXPECT_FALSE(t->mss.has_value());  // after End of Option List, so padding
    EXPECT_FALSE(t->options_malformed);
}

TEST(TcpDecode, AMalformedOptionIsRecordedAndTheHeaderStillRead) {
    const auto s = tcpHeader(6, {0x02, 0x09, 0x05, 0xB4});
    const auto t = decodeTcp(s.data(), s.size());
    ASSERT_TRUE(t.has_value());
    EXPECT_TRUE(t->options_malformed);
    EXPECT_EQ(t->window, 0xFFFF);
}

TEST(TcpDecode, AHeaderThatCannotBeLocatedIsNothing) {
    const auto shortish = tcpHeader(5, {});
    EXPECT_FALSE(decodeTcp(shortish.data(), 19).has_value());
    const auto low = tcpHeader(4, {});
    EXPECT_FALSE(decodeTcp(low.data(), low.size()).has_value());
    const auto past = tcpHeader(8, {});
    EXPECT_FALSE(decodeTcp(past.data(), past.size()).has_value());
}

}  // namespace
