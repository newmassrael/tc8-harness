#include <string>

#include <gtest/gtest.h>

#include "capture/bpf_filter.h"
#include "tc8/bpf_group.h"
#include "tc8/dut_config.h"

namespace tc8::capture::bpf {
namespace {

TEST(BpfFilter, PerGroupExpressionsAreNonEmpty) {
    EXPECT_FALSE(arp().empty());
    EXPECT_FALSE(icmpv4().empty());
    EXPECT_FALSE(ipv4().empty());
    EXPECT_FALSE(udp().empty());
    EXPECT_FALSE(dhcpv4().empty());
    EXPECT_FALSE(tcp().empty());
    EXPECT_FALSE(someip().empty());
    EXPECT_FALSE(arpAndUdp().empty());
    EXPECT_FALSE(arpAndDhcpv4().empty());
}

TEST(BpfFilter, ArpAndUdpLiteral) {
    EXPECT_EQ(arpAndUdp(), "arp or udp");
}

TEST(BpfFilter, ArpAndDhcpv4LiteralPinsBootpPorts) {
    const std::string expr = arpAndDhcpv4();
    EXPECT_NE(expr.find("arp"), std::string::npos) << expr;
    EXPECT_NE(expr.find("67"),  std::string::npos) << expr;
    EXPECT_NE(expr.find("68"),  std::string::npos) << expr;
}

TEST(BpfFilter, Ipv4Literal) {
    // Pinned so the §4.4 IPv4 pilot's capture filter cannot silently
    // widen back to "ip or arp" and double-deliver ARP traffic to a
    // listener that has none of its variants registered.
    EXPECT_EQ(ipv4(), "ip");
}

TEST(BpfFilter, DhcpReferencesBootpPorts) {
    const std::string expr = dhcpv4();
    EXPECT_NE(expr.find("67"), std::string::npos) << expr;
    EXPECT_NE(expr.find("68"), std::string::npos) << expr;
}

TEST(BpfFilter, PortRangeLiteral) {
    EXPECT_EQ(portRange(100, 200), "udp portrange 100-200 or tcp portrange 100-200");
}

TEST(BpfFilter, SomeIpUsesMockCaptureWindow) {
    const std::string expr = someip();
    const std::string lo = std::to_string(::tc8::dut::kCapturePortLow);
    const std::string hi = std::to_string(::tc8::dut::kCapturePortHigh);
    EXPECT_NE(expr.find(lo), std::string::npos) << expr;
    EXPECT_NE(expr.find(hi), std::string::npos) << expr;
}

TEST(BpfFilter, ExpressionForMatchesPerGroupFunction) {
    using ::tc8::BpfGroup;
    EXPECT_EQ(expressionFor(BpfGroup::Arp), arp());
    EXPECT_EQ(expressionFor(BpfGroup::Icmpv4), icmpv4());
    EXPECT_EQ(expressionFor(BpfGroup::Ipv4), ipv4());
    EXPECT_EQ(expressionFor(BpfGroup::Udp), udp());
    EXPECT_EQ(expressionFor(BpfGroup::Dhcpv4), dhcpv4());
    EXPECT_EQ(expressionFor(BpfGroup::Tcp), tcp());
    EXPECT_EQ(expressionFor(BpfGroup::SomeIp), someip());
    EXPECT_EQ(expressionFor(BpfGroup::ArpAndUdp), arpAndUdp());
    EXPECT_EQ(expressionFor(BpfGroup::ArpAndDhcpv4), arpAndDhcpv4());
}

}  // namespace
}  // namespace tc8::capture::bpf
