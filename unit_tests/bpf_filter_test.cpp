#include <optional>
#include <string>

#include <gtest/gtest.h>

#include <pcap/pcap.h>

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

TEST(BpfFilter, VlanAwareWrapsBothTaggedAndUntagged) {
    // The wrapper must keep the bare predicate as the first arm (matches
    // untagged frames) and add a `vlan and (...)` second arm (matches the
    // tagged copy, where the 4-byte tag shifts every later field).
    EXPECT_EQ(vlanAware("arp"), "(arp) or (vlan and (arp))");
}

TEST(BpfFilter, ExpressionForIsVlanAwareWrapOfPerGroupFunction) {
    // expressionFor dispatches to the bare per-group function AND applies
    // VLAN-awareness once at the boundary, so every case capture filter
    // tolerates a single 802.1Q tag. The per-group functions themselves
    // stay bare (testable building blocks); the wrap lives only here.
    using ::tc8::BpfGroup;
    EXPECT_EQ(expressionFor(BpfGroup::Arp), vlanAware(arp()));
    EXPECT_EQ(expressionFor(BpfGroup::Icmpv4), vlanAware(icmpv4()));
    EXPECT_EQ(expressionFor(BpfGroup::Ipv4), vlanAware(ipv4()));
    EXPECT_EQ(expressionFor(BpfGroup::Udp), vlanAware(udp()));
    EXPECT_EQ(expressionFor(BpfGroup::Dhcpv4), vlanAware(dhcpv4()));
    EXPECT_EQ(expressionFor(BpfGroup::Tcp), vlanAware(tcp()));
    EXPECT_EQ(expressionFor(BpfGroup::SomeIp), vlanAware(someip()));
    EXPECT_EQ(expressionFor(BpfGroup::ArpAndUdp), vlanAware(arpAndUdp()));
    EXPECT_EQ(expressionFor(BpfGroup::ArpAndDhcpv4), vlanAware(arpAndDhcpv4()));
    EXPECT_EQ(expressionFor(BpfGroup::UdpAndDhcpv4), vlanAware(udpAndDhcpv4()));
}

TEST(BpfFilter, ResolveCaptureFilterPrecedence) {
    using ::tc8::BpfGroup;
    // 1. CLI -f override wins and is passed verbatim (even over a
    //    per-case expression).
    EXPECT_EQ(resolveCaptureFilter(std::optional<std::string>("ether host 1:2:3:4:5:6"),
                                   "udp port 5000", BpfGroup::Arp),
              "ether host 1:2:3:4:5:6");
    // 2. No override + a per-case kBpfExpression → used verbatim (the
    //    out-of-tree escape hatch; not VLAN-wrapped — the case owns that).
    EXPECT_EQ(resolveCaptureFilter(std::nullopt, "udp port 5000", BpfGroup::Arp),
              "udp port 5000");
    // 3. No override + empty per-case expression → the VLAN-aware
    //    kBpfGroup filter (the normal path for every in-tree case).
    EXPECT_EQ(resolveCaptureFilter(std::nullopt, "", BpfGroup::Arp),
              vlanAware(arp()));
}

TEST(BpfFilter, EveryExpressionCompilesUnderLibpcap) {
    // The VLAN-aware wrap injects libpcap's `vlan` keyword, which only
    // some expression shapes accept cleanly. Compile every group's filter
    // against a dead DLT_EN10MB handle so a syntactically-invalid wrap is
    // caught here — hermetically, without the netns smoke run — rather
    // than at `applyBpf()` on a live capture.
    using ::tc8::BpfGroup;
    pcap_t *dead = pcap_open_dead(DLT_EN10MB, 65535);
    ASSERT_NE(dead, nullptr);

    const BpfGroup groups[] = {
        BpfGroup::Arp,        BpfGroup::Icmpv4,      BpfGroup::Ipv4,
        BpfGroup::Udp,        BpfGroup::Dhcpv4,      BpfGroup::Tcp,
        BpfGroup::SomeIp,     BpfGroup::ArpAndUdp,   BpfGroup::ArpAndDhcpv4,
        BpfGroup::UdpAndDhcpv4,
    };
    for (const auto g : groups) {
        const std::string expr = expressionFor(g);
        bpf_program prog{};
        const int rc =
            pcap_compile(dead, &prog, expr.c_str(), 1, PCAP_NETMASK_UNKNOWN);
        EXPECT_EQ(rc, 0) << "pcap_compile rejected: " << expr << " — "
                         << pcap_geterr(dead);
        if (rc == 0) {
            pcap_freecode(&prog);
        }
    }
    pcap_close(dead);
}

}  // namespace
}  // namespace tc8::capture::bpf
