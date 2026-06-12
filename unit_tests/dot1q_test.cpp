// Unit tests for the 802.1Q stimulus builder (tc8::stimulus::withDot1QTag).
//
// The first test round-trips a built frame through libtins — the SAME
// decoder tc8::dissect::PacketPipeline uses — so the encode side and the
// decode side cannot drift apart. The remaining tests pin the exact wire
// byte layout, the PCP/VID field masking, and the short-frame no-op.

#include "stimulus/dot1q.h"

#include <gtest/gtest.h>

#include <tins/arp.h>
#include <tins/dot1q.h>
#include <tins/ethernetII.h>

#include <cstdint>
#include <vector>

namespace {

using namespace Tins;

// Build a complete untagged Ethernet-II/ARP frame as raw bytes.
std::vector<std::uint8_t> buildUntaggedArpFrame() {
    EthernetII eth("ff:ff:ff:ff:ff:ff", "02:00:00:00:00:a1");
    ARP arp;
    arp.opcode(ARP::REQUEST);
    arp.sender_hw_addr("02:00:00:00:00:a1");
    arp.sender_ip_addr("172.16.0.1");
    arp.target_ip_addr("172.16.0.2");
    eth /= arp;
    const auto buf = eth.serialize();
    return std::vector<std::uint8_t>(buf.begin(), buf.end());
}

TEST(Dot1QBuilder, RoundTripThroughLibtins) {
    const auto untagged = buildUntaggedArpFrame();
    const std::uint8_t pcp = 5;
    const bool dei = true;
    const std::uint16_t vid = 100;

    const auto tagged = tc8::stimulus::withDot1QTag(untagged, pcp, dei, vid);
    EXPECT_EQ(tagged.size(), untagged.size() + 4U);

    // Decode with the production decoder.
    EthernetII eth(tagged.data(), static_cast<std::uint32_t>(tagged.size()));
    const Dot1Q *q = eth.find_pdu<Dot1Q>();
    ASSERT_NE(q, nullptr);
    EXPECT_EQ(static_cast<unsigned>(q->priority()), pcp);
    EXPECT_EQ(static_cast<unsigned>(q->cfi()), 1U);
    EXPECT_EQ(static_cast<unsigned>(q->id()), vid);

    // `find_pdu` descends through the tag — the inner ARP must still be
    // reachable, which is exactly the assumption the pipeline relies on
    // when it looks up ARP/IP/ICMP/UDP/TCP behind a Dot1Q layer.
    const ARP *arp = eth.find_pdu<ARP>();
    ASSERT_NE(arp, nullptr);
    EXPECT_EQ(arp->opcode(), ARP::REQUEST);
}

TEST(Dot1QBuilder, ByteLayoutMatchesContract) {
    const auto untagged = buildUntaggedArpFrame();
    const std::uint16_t orig_ethertype =
        static_cast<std::uint16_t>((untagged[12] << 8) | untagged[13]);  // 0x0806

    const auto tagged =
        tc8::stimulus::withDot1QTag(untagged, /*pcp=*/3, /*dei=*/false, /*vid=*/0xABC);

    // Destination + source MAC preserved verbatim.
    for (int i = 0; i < 12; ++i) {
        EXPECT_EQ(tagged[static_cast<std::size_t>(i)], untagged[static_cast<std::size_t>(i)]);
    }
    // TPID 0x8100 at offset 12..13.
    EXPECT_EQ(tagged[12], 0x81);
    EXPECT_EQ(tagged[13], 0x00);
    // TCI = PCP(3)<<13 | DEI<<12 | VID = 0x6ABC at offset 14..15.
    const std::uint16_t tci = static_cast<std::uint16_t>((tagged[14] << 8) | tagged[15]);
    EXPECT_EQ(tci, static_cast<std::uint16_t>((3U << 13) | 0xABCU));
    // Original EtherType relocated to offset 16..17.
    const std::uint16_t inner = static_cast<std::uint16_t>((tagged[16] << 8) | tagged[17]);
    EXPECT_EQ(inner, orig_ethertype);
}

TEST(Dot1QBuilder, PcpAndVidMasked) {
    const auto untagged = buildUntaggedArpFrame();
    // PCP 0xFF masks to 0x7, VID 0xFFFF masks to 0x0FFF, DEI set.
    const auto tagged = tc8::stimulus::withDot1QTag(untagged, 0xFF, true, 0xFFFF);
    const std::uint16_t tci = static_cast<std::uint16_t>((tagged[14] << 8) | tagged[15]);
    EXPECT_EQ(tci, static_cast<std::uint16_t>((0x7U << 13) | (1U << 12) | 0x0FFFU));
}

TEST(Dot1QBuilder, ShortFrameReturnedUnchanged) {
    const std::vector<std::uint8_t> tiny{0x01, 0x02, 0x03};
    const auto out = tc8::stimulus::withDot1QTag(tiny, 1, false, 1);
    EXPECT_EQ(out, tiny);
}

}  // namespace
