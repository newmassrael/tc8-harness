#include <array>
#include <cstdint>
#include <vector>

#include <gtest/gtest.h>

#include "stimulus/arp_builder.h"

namespace tc8::stimulus {
namespace {

// 172.16.0.1 in network byte order (what `inet_pton` writes on
// little-endian): 0xAC 0x10 0x00 0x01 → uint32 0x010010AC.
constexpr std::uint32_t kTesterIpBe = 0x010010AC;
// 172.16.0.2 equivalently → 0x020010AC.
constexpr std::uint32_t kDutIpBe = 0x020010AC;
constexpr std::array<std::uint8_t, 6> kSenderHw{0x02, 0x00, 0x00, 0x00, 0x00, 0xA1};

TEST(BuildArpRequest, TotalSizeIs42Bytes) {
    const auto b = buildArpRequest(kSenderHw, kTesterIpBe, kDutIpBe);
    EXPECT_EQ(b.size(), 42u);
}

TEST(BuildArpRequest, EthernetHeaderHasBroadcastDstAndArpType) {
    const auto b = buildArpRequest(kSenderHw, kTesterIpBe, kDutIpBe);
    ASSERT_GE(b.size(), 14u);
    for (int i = 0; i < 6; ++i) {
        EXPECT_EQ(b[static_cast<std::size_t>(i)], 0xFF) << "eth-dst[" << i << "]";
    }
    for (int i = 0; i < 6; ++i) {
        EXPECT_EQ(b[6u + static_cast<std::size_t>(i)], kSenderHw[static_cast<std::size_t>(i)])
            << "eth-src[" << i << "]";
    }
    EXPECT_EQ(b[12], 0x08);  // ethertype high
    EXPECT_EQ(b[13], 0x06);  // ethertype low
}

TEST(BuildArpRequest, ArpPayloadShape) {
    const auto b = buildArpRequest(kSenderHw, kTesterIpBe, kDutIpBe);
    ASSERT_GE(b.size(), 42u);
    // ARP starts at offset 14.
    EXPECT_EQ(b[14], 0x00);  // htype high
    EXPECT_EQ(b[15], 0x01);  // htype = 1 (Ethernet)
    EXPECT_EQ(b[16], 0x08);  // ptype high
    EXPECT_EQ(b[17], 0x00);  // ptype = 0x0800 (IPv4)
    EXPECT_EQ(b[18], 0x06);  // hlen
    EXPECT_EQ(b[19], 0x04);  // plen
    EXPECT_EQ(b[20], 0x00);  // opcode high
    EXPECT_EQ(b[21], 0x01);  // opcode = 1 (Request)
    // sender_hw at [22..27]
    for (int i = 0; i < 6; ++i) {
        EXPECT_EQ(b[22u + static_cast<std::size_t>(i)], kSenderHw[static_cast<std::size_t>(i)])
            << "sender_hw[" << i << "]";
    }
    // sender_ip at [28..31] — stored in network byte order (MSB-first).
    EXPECT_EQ(b[28], 0xAC);
    EXPECT_EQ(b[29], 0x10);
    EXPECT_EQ(b[30], 0x00);
    EXPECT_EQ(b[31], 0x01);
    // target_hw at [32..37] — zero for Request.
    for (int i = 0; i < 6; ++i) {
        EXPECT_EQ(b[32u + static_cast<std::size_t>(i)], 0x00) << "target_hw[" << i << "]";
    }
    // target_ip at [38..41] — DUT IP.
    EXPECT_EQ(b[38], 0xAC);
    EXPECT_EQ(b[39], 0x10);
    EXPECT_EQ(b[40], 0x00);
    EXPECT_EQ(b[41], 0x02);
}

TEST(BuildGratuitousArpResponse, OpcodeIsTwoAndSenderEqualsTarget) {
    const auto b = buildGratuitousArpResponse(kSenderHw, kTesterIpBe);
    ASSERT_EQ(b.size(), 42u);
    EXPECT_EQ(b[20], 0x00);  // opcode high
    EXPECT_EQ(b[21], 0x02);  // opcode = 2 (Reply)
    // sender_hw at [22..27] and target_hw at [32..37] must match.
    for (int i = 0; i < 6; ++i) {
        EXPECT_EQ(b[22u + static_cast<std::size_t>(i)], b[32u + static_cast<std::size_t>(i)])
            << "sender/target hw mismatch at byte " << i;
    }
    // sender_ip at [28..31] must equal target_ip at [38..41].
    for (int i = 0; i < 4; ++i) {
        EXPECT_EQ(b[28u + static_cast<std::size_t>(i)], b[38u + static_cast<std::size_t>(i)])
            << "sender/target ip mismatch at byte " << i;
    }
}

TEST(BuildGratuitousArpResponse, EthernetDstIsBroadcast) {
    const auto b = buildGratuitousArpResponse(kSenderHw, kTesterIpBe);
    ASSERT_GE(b.size(), 6u);
    for (int i = 0; i < 6; ++i) {
        EXPECT_EQ(b[static_cast<std::size_t>(i)], 0xFF) << "eth-dst[" << i << "]";
    }
}

TEST(BuildArpFrame, FullSpecPassThrough) {
    // Every field on ArpFrameSpec maps 1:1 to a wire byte position; the
    // generic builder exists so §4.2.4.2 Phase 3 cases can vary one field
    // (hw_type, proto_type, opcode, target_hw, ...) while keeping the rest
    // at RFC 826 defaults. Verify each override lands where the dissector
    // expects to read it.
    ArpFrameSpec spec;
    spec.eth_dst = {0x11, 0x22, 0x33, 0x44, 0x55, 0x66};
    spec.eth_src = {0x77, 0x88, 0x99, 0xAA, 0xBB, 0xCC};
    spec.hw_type = 0xBEEF;
    spec.proto_type = 0xDEAD;
    spec.hw_addr_len = 6;
    spec.proto_addr_len = 4;
    spec.opcode = 0x0002;  // Reply
    spec.sender_hw = {0x10, 0x20, 0x30, 0x40, 0x50, 0x60};
    spec.sender_ip_be = kTesterIpBe;
    spec.target_hw = {0x70, 0x80, 0x90, 0xA0, 0xB0, 0xC0};
    spec.target_ip_be = kDutIpBe;

    const auto b = buildArpFrame(spec);
    ASSERT_EQ(b.size(), 42u);
    // Ethernet dst / src pin
    for (int i = 0; i < 6; ++i) {
        EXPECT_EQ(b[static_cast<std::size_t>(i)], spec.eth_dst[static_cast<std::size_t>(i)]) << "eth_dst[" << i << "]";
        EXPECT_EQ(b[6u + static_cast<std::size_t>(i)], spec.eth_src[static_cast<std::size_t>(i)])
            << "eth_src[" << i << "]";
    }
    EXPECT_EQ(b[12], 0x08);
    EXPECT_EQ(b[13], 0x06);  // ethertype ARP
    EXPECT_EQ(b[14], 0xBE);
    EXPECT_EQ(b[15], 0xEF);  // hw_type
    EXPECT_EQ(b[16], 0xDE);
    EXPECT_EQ(b[17], 0xAD);  // proto_type
    EXPECT_EQ(b[18], 0x06);
    EXPECT_EQ(b[19], 0x04);  // hw/proto lens
    EXPECT_EQ(b[20], 0x00);
    EXPECT_EQ(b[21], 0x02);  // opcode = Reply
    for (int i = 0; i < 6; ++i) {
        EXPECT_EQ(b[22u + static_cast<std::size_t>(i)], spec.sender_hw[static_cast<std::size_t>(i)]);
        EXPECT_EQ(b[32u + static_cast<std::size_t>(i)], spec.target_hw[static_cast<std::size_t>(i)]);
    }
}

TEST(BuildArpFrame, EthSrcDefaultsToSenderHw) {
    // Wire convention for ARP: Ethernet source = ARP sender_hw unless the
    // test explicitly exercises the asymmetric path (ARP_43). With eth_src
    // left at its zero-initialised default the builder must fall back to
    // sender_hw so callers don't have to set the Ethernet field twice.
    ArpFrameSpec spec;
    spec.sender_hw = kSenderHw;
    spec.sender_ip_be = kTesterIpBe;
    spec.target_ip_be = kDutIpBe;
    // spec.eth_src left at default = all zeroes

    const auto b = buildArpFrame(spec);
    for (int i = 0; i < 6; ++i) {
        EXPECT_EQ(b[6u + static_cast<std::size_t>(i)], kSenderHw[static_cast<std::size_t>(i)])
            << "eth_src should default to sender_hw at byte " << i;
    }
}

TEST(BuildArpRequestWrapper, EquivalentToGenericBuilder) {
    // The old one-shot API is now a thin wrapper — guarantee byte-for-byte
    // equivalence so callers can choose whichever spelling reads clearer
    // without behavior drift.
    const auto wrapped = buildArpRequest(kSenderHw, kTesterIpBe, kDutIpBe);

    ArpFrameSpec spec;
    spec.sender_hw = kSenderHw;
    spec.sender_ip_be = kTesterIpBe;
    spec.target_ip_be = kDutIpBe;
    const auto direct = buildArpFrame(spec);

    ASSERT_EQ(wrapped, direct);
}

TEST(InjectedMacConstant, IsLocallyAdministeredUnicast) {
    // RFC 7042 §2.1: the locally-administered bit is the second-LSB of
    // the first octet; the multicast bit is the LSB. All three injected
    // MAC constants (MAC1 for §4.2.4.1 ARP_03..06 + Phase 3a/b cases,
    // MAC2 for Group C cache-merge + Group D ARP_39, MAC3 for Group D
    // ARP_40 Response-form learning) must set the locally-administered
    // bit and clear the multicast bit so the harness never injects
    // multicast/broadcast-looking MACs.
    EXPECT_EQ(kTesterInjectedMac[0] & 0x02, 0x02);
    EXPECT_EQ(kTesterInjectedMac[0] & 0x01, 0x00);
    EXPECT_EQ(kTesterInjectedMac2[0] & 0x02, 0x02);
    EXPECT_EQ(kTesterInjectedMac2[0] & 0x01, 0x00);
    EXPECT_EQ(kTesterInjectedMac3[0] & 0x02, 0x02);
    EXPECT_EQ(kTesterInjectedMac3[0] & 0x01, 0x00);
    // Per-MAC distinctness — drift would silently turn cache-merge /
    // dual-injection cases into false passes if two of the constants
    // collided.
    EXPECT_NE(kTesterInjectedMac, kTesterInjectedMac2);
    EXPECT_NE(kTesterInjectedMac, kTesterInjectedMac3);
    EXPECT_NE(kTesterInjectedMac2, kTesterInjectedMac3);
}

}  // namespace
}  // namespace tc8::stimulus
