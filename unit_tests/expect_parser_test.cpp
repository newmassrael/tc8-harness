#include <array>
#include <cstdint>

#include <gtest/gtest.h>

#include "cli/expect_parser.h"
#include "sce_integration/arp_expectations.h"
#include "sce_integration/dhcpv4_expectations.h"
#include "sce_integration/someip_expectations.h"

namespace tc8::cli {
namespace {

TEST(ParseNumeric, AcceptsDecimal) {
    std::uint64_t n = 0;
    ASSERT_TRUE(parseNumeric("42", n));
    EXPECT_EQ(n, 42u);
}

TEST(ParseNumeric, AcceptsHex) {
    std::uint64_t n = 0;
    ASSERT_TRUE(parseNumeric("0xF4E7", n));
    EXPECT_EQ(n, 0xF4E7u);
}

TEST(ParseNumeric, RejectsEmpty) {
    std::uint64_t n = 0;
    EXPECT_FALSE(parseNumeric("", n));
}

TEST(ParseNumeric, RejectsTrailingGarbage) {
    std::uint64_t n = 0;
    EXPECT_FALSE(parseNumeric("0x10ff_junk", n));
    EXPECT_FALSE(parseNumeric("123abc", n));
}

TEST(ParseNumeric, RejectsNonNumeric) {
    std::uint64_t n = 0;
    EXPECT_FALSE(parseNumeric("abc", n));
}

TEST(ApplyExpectToken, ServiceIdRoundTrip) {
    ::tc8::SomeIpExpectations e{};
    ASSERT_TRUE(applyExpectToken("service_id=0xF4E7", e));
    EXPECT_EQ(e.service_id, 0xF4E7);
}

TEST(ApplyExpectToken, AllRecognisedKeys) {
    ::tc8::SomeIpExpectations e{};
    EXPECT_TRUE(applyExpectToken("service_id=0x1234", e));
    EXPECT_TRUE(applyExpectToken("instance_id=0x5678", e));
    EXPECT_TRUE(applyExpectToken("major_version=2", e));
    EXPECT_TRUE(applyExpectToken("ttl=3", e));
    EXPECT_TRUE(applyExpectToken("minor_version=0", e));
    EXPECT_TRUE(applyExpectToken("eventgroup_id=0x0042", e));
    EXPECT_EQ(e.service_id, 0x1234);
    EXPECT_EQ(e.instance_id, 0x5678);
    EXPECT_EQ(e.major_version, 2);
    EXPECT_EQ(e.ttl, 3u);
    EXPECT_EQ(e.minor_version, 0u);
    EXPECT_EQ(e.eventgroup_id, 0x0042);
}

TEST(ApplyExpectToken, RejectsOverflowServiceId) {
    ::tc8::SomeIpExpectations e{};
    EXPECT_FALSE(applyExpectToken("service_id=0x10000", e));
    EXPECT_EQ(e.service_id, 0);
}

TEST(ApplyExpectToken, RejectsOverflowMajorVersion) {
    ::tc8::SomeIpExpectations e{};
    EXPECT_FALSE(applyExpectToken("major_version=256", e));
}

TEST(ApplyExpectToken, RejectsOverflowTtl24Bit) {
    // SD TTL is 24-bit, so 0x1000000 must be rejected.
    ::tc8::SomeIpExpectations e{};
    EXPECT_FALSE(applyExpectToken("ttl=0x1000000", e));
    EXPECT_TRUE(applyExpectToken("ttl=0xFFFFFF", e));
    EXPECT_EQ(e.ttl, 0xFFFFFFu);
}

TEST(ApplyExpectToken, RejectsMissingEquals) {
    ::tc8::SomeIpExpectations e{};
    EXPECT_FALSE(applyExpectToken("service_id0xF4E7", e));
}

TEST(ApplyExpectToken, RejectsUnknownKey) {
    ::tc8::SomeIpExpectations e{};
    EXPECT_FALSE(applyExpectToken("client_id=0", e));
}

TEST(ApplyExpectToken, RejectsEmptyValue) {
    ::tc8::SomeIpExpectations e{};
    EXPECT_FALSE(applyExpectToken("service_id=", e));
}

TEST(ParseIpv4Dotted, RoundTripsTopologyAddresses) {
    std::uint32_t ip = 0;
    ASSERT_TRUE(parseIpv4Dotted("172.16.0.1", ip));
    // Network byte order: 172=0xAC, 16=0x10, 0=0x00, 1=0x01 — wire layout
    // AC.10.00.01 → s_addr little-endian on x86 reads 0x0100 10AC.
    EXPECT_EQ(ip, 0x0100'10ACu);

    ASSERT_TRUE(parseIpv4Dotted("172.16.0.2", ip));
    EXPECT_EQ(ip, 0x0200'10ACu);
}

TEST(ParseIpv4Dotted, AcceptsBoundaryValues) {
    std::uint32_t ip = 0;
    EXPECT_TRUE(parseIpv4Dotted("0.0.0.0", ip));
    EXPECT_EQ(ip, 0u);
    EXPECT_TRUE(parseIpv4Dotted("255.255.255.255", ip));
    EXPECT_EQ(ip, 0xFFFF'FFFFu);
}

TEST(ParseIpv4Dotted, RejectsBadInput) {
    std::uint32_t ip = 0;
    EXPECT_FALSE(parseIpv4Dotted("", ip));
    EXPECT_FALSE(parseIpv4Dotted("not.an.ip.address", ip));
    EXPECT_FALSE(parseIpv4Dotted("256.0.0.1", ip));
    EXPECT_FALSE(parseIpv4Dotted("1.2.3", ip));
    EXPECT_FALSE(parseIpv4Dotted("1.2.3.4.5", ip));
}

TEST(ParseMac, RoundTripsLowercase) {
    std::array<std::uint8_t, 6> mac{};
    ASSERT_TRUE(parseMac("aa:bb:cc:dd:ee:ff", mac));
    const std::array<std::uint8_t, 6> expected{0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF};
    EXPECT_EQ(mac, expected);
}

TEST(ParseMac, AcceptsUppercaseAndSingleDigitOctets) {
    std::array<std::uint8_t, 6> mac{};
    ASSERT_TRUE(parseMac("0:1:A:B:c:d", mac));
    const std::array<std::uint8_t, 6> expected{0x00, 0x01, 0x0A, 0x0B, 0x0C, 0x0D};
    EXPECT_EQ(mac, expected);
}

TEST(ParseMac, RejectsBadInput) {
    std::array<std::uint8_t, 6> mac{};
    EXPECT_FALSE(parseMac("", mac));
    EXPECT_FALSE(parseMac("aa:bb:cc:dd:ee", mac));        // 5 octets
    EXPECT_FALSE(parseMac("aa:bb:cc:dd:ee:ff:11", mac));  // 7 octets
    EXPECT_FALSE(parseMac("aa-bb-cc-dd-ee-ff", mac));     // wrong separator
    EXPECT_FALSE(parseMac("aa:bb:cc:dd:ee:zz", mac));     // non-hex
    EXPECT_FALSE(parseMac("aaa:bb:cc:dd:ee:ff", mac));    // 3-digit octet
}

TEST(ApplyExpectToken_Arp, AcceptsAllArpKeys) {
    ::tc8::ArpExpectations e{};
    EXPECT_TRUE(applyExpectToken("arp.dut_iface_ip=172.16.0.2", e));
    EXPECT_TRUE(applyExpectToken("arp.tester_ip=172.16.0.1", e));
    EXPECT_TRUE(applyExpectToken("arp.dut_iface_mac=aa:bb:cc:dd:ee:ff", e));
    EXPECT_TRUE(applyExpectToken("arp.tester_mac=02:00:00:00:00:A1", e));
    EXPECT_TRUE(applyExpectToken("arp.dut_real_ip=172.16.0.2", e));
    EXPECT_TRUE(applyExpectToken("arp.dut_real_mac=11:22:33:44:55:66", e));
    EXPECT_TRUE(applyExpectToken("arp.tester_mac2=02:00:00:00:00:A2", e));
    EXPECT_TRUE(applyExpectToken("arp.tester_mac3=02:00:00:00:00:A3", e));
    EXPECT_EQ(e.dut_iface_ip, 0x0200'10ACu);
    EXPECT_EQ(e.tester_ip, 0x0100'10ACu);
    const std::array<std::uint8_t, 6> expected_mac{0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF};
    EXPECT_EQ(e.dut_iface_mac, expected_mac);
    const std::array<std::uint8_t, 6> expected_tester_mac{0x02, 0x00, 0x00, 0x00, 0x00, 0xA1};
    EXPECT_EQ(e.tester_mac, expected_tester_mac);
    EXPECT_EQ(e.dut_real_ip, 0x0200'10ACu);
    const std::array<std::uint8_t, 6> expected_real_mac{0x11, 0x22, 0x33, 0x44, 0x55, 0x66};
    EXPECT_EQ(e.dut_real_mac, expected_real_mac);
    const std::array<std::uint8_t, 6> expected_tester_mac2{0x02, 0x00, 0x00, 0x00, 0x00, 0xA2};
    EXPECT_EQ(e.tester_mac2, expected_tester_mac2);
    const std::array<std::uint8_t, 6> expected_tester_mac3{0x02, 0x00, 0x00, 0x00, 0x00, 0xA3};
    EXPECT_EQ(e.tester_mac3, expected_tester_mac3);
}

TEST(ApplyExpectToken_Arp, RejectsMissingPrefix) {
    ::tc8::ArpExpectations e{};
    // Bare key without the `arp.` prefix is not the ARP overload's
    // responsibility — it would be a SOME/IP key, but here we verify the
    // ARP overload itself returns false so the chain in test_command can
    // fall through correctly.
    EXPECT_FALSE(applyExpectToken("dut_iface_ip=172.16.0.2", e));
    EXPECT_FALSE(applyExpectToken("tester_ip=172.16.0.1", e));
}

TEST(ApplyExpectToken_Arp, RejectsUnknownArpKey) {
    ::tc8::ArpExpectations e{};
    EXPECT_FALSE(applyExpectToken("arp.bogus=1", e));
}

TEST(ApplyExpectToken_Arp, RejectsMalformedValue) {
    ::tc8::ArpExpectations e{};
    EXPECT_FALSE(applyExpectToken("arp.dut_iface_ip=999.0.0.1", e));
    EXPECT_FALSE(applyExpectToken("arp.dut_iface_mac=aa:bb:cc:dd:ee", e));
    EXPECT_FALSE(applyExpectToken("arp.tester_mac=aa:bb:cc:dd:ee", e));
    EXPECT_FALSE(applyExpectToken("arp.dut_real_ip=999.0.0.1", e));
    EXPECT_FALSE(applyExpectToken("arp.dut_real_mac=aa:bb:cc:dd:ee", e));
    EXPECT_FALSE(applyExpectToken("arp.tester_mac2=aa:bb:cc:dd:ee", e));
    EXPECT_FALSE(applyExpectToken("arp.tester_mac3=aa:bb:cc:dd:ee", e));
}

TEST(ApplyExpectToken_Dhcpv4, AcceptsDutIfaceMac) {
    ::tc8::Dhcpv4Expectations e{};
    EXPECT_TRUE(applyExpectToken("dhcpv4.dut_iface_mac=aa:bb:cc:dd:ee:ff", e));
    const std::array<std::uint8_t, 6> expected{0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF};
    EXPECT_EQ(e.dut_iface_mac, expected);
}

TEST(ApplyExpectToken_Dhcpv4, RejectsMissingPrefix) {
    ::tc8::Dhcpv4Expectations e{};
    EXPECT_FALSE(applyExpectToken("dut_iface_mac=aa:bb:cc:dd:ee:ff", e));
}

TEST(ApplyExpectToken_Dhcpv4, RejectsUnknownKey) {
    ::tc8::Dhcpv4Expectations e{};
    EXPECT_FALSE(applyExpectToken("dhcpv4.bogus=1", e));
}

TEST(ApplyExpectToken_Dhcpv4, RejectsMalformedValue) {
    ::tc8::Dhcpv4Expectations e{};
    EXPECT_FALSE(applyExpectToken("dhcpv4.dut_iface_mac=aa:bb:cc:dd:ee", e));
}

}  // namespace
}  // namespace tc8::cli
