// Pins the SOME/IP Method Request destination helper
// (sce_integration/someip_method_dest.h): the DUT endpoint must derive from
// the configured `cfg.someip` (the `--expect` surface), with port_override for
// spawn-variant ports and a zero sentinel — never a baked-in literal — when
// unconfigured. The byte-order contract (ipv4_be NBO, port host order) is the
// make-or-break detail, so these assertions are the SSOT gate for the 153
// migrated Method Request call sites.

#include <gtest/gtest.h>

#include <cstdint>

#include "sce_integration/someip_method_dest.h"
#include "sce_integration/test_config.h"

namespace {

constexpr std::uint32_t kDutIpBe = 0x020010ACu;  // 172.16.0.2 in network byte order
constexpr std::uint16_t kUdpPort = 30502;        // services[0] unreliable
constexpr std::uint16_t kTcpPort = 30501;        // services[0] reliable

tc8::TestConfig configured() {
    tc8::TestConfig cfg{};
    cfg.someip.dut_iface_ip = kDutIpBe;
    cfg.someip.udp_port = kUdpPort;
    cfg.someip.tcp_port = kTcpPort;
    return cfg;
}

TEST(SomeipMethodDest, UdpDerivesConfiguredEndpoint) {
    const auto d = tc8::sce::someipUdpMethodDest(configured());
    EXPECT_EQ(d.ipv4_be, kDutIpBe);  // NBO passes straight through
    EXPECT_EQ(d.port, kUdpPort);
}

// Regression guard for the TCP-port-leak footgun: the TCP helper must source
// tcp_port, never the UDP port, and never a struct default.
TEST(SomeipMethodDest, TcpUsesTcpPortNotUdpPort) {
    const auto d = tc8::sce::someipTcpMethodDest(configured());
    EXPECT_EQ(d.ipv4_be, kDutIpBe);
    EXPECT_EQ(d.port, kTcpPort);
    EXPECT_NE(d.port, kUdpPort);
}

TEST(SomeipMethodDest, PortOverrideWinsIpStillFromCfg) {
    const auto d = tc8::sce::someipUdpMethodDest(configured(), tc8::sce::someip::kSi2UdpPort);
    EXPECT_EQ(d.ipv4_be, kDutIpBe);
    EXPECT_EQ(d.port, tc8::sce::someip::kSi2UdpPort);
}

// Unconfigured run yields a 0.0.0.0:0 sentinel (fail-loud on connect), NOT the
// former hardcoded 172.16.0.2:30502 literal.
TEST(SomeipMethodDest, UnsetYieldsSentinelNotLiteral) {
    const tc8::TestConfig empty{};
    const auto d = tc8::sce::someipUdpMethodDest(empty);
    EXPECT_EQ(d.ipv4_be, 0u);
    EXPECT_EQ(d.port, 0u);
}

TEST(SomeipMethodDest, OverrideHonoredEvenWithUnsetIp) {
    const tc8::TestConfig empty{};
    const auto d = tc8::sce::someipTcpMethodDest(empty, tc8::sce::someip::kSi1Inst2TcpPort);
    EXPECT_EQ(d.ipv4_be, 0u);
    EXPECT_EQ(d.port, tc8::sce::someip::kSi1Inst2TcpPort);
}

}  // namespace
