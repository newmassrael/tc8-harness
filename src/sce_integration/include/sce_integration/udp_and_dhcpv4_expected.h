#pragma once

#include <array>
#include <cstdint>

#include "dhcpv4_default_endpoints.h"
#include "dhcpv4_expected.h"
#include "stimulus/arp_builder.h"  // kTesterInjectedMac
#include "test_config.h"

namespace tc8 {

// Cross-protocol expected for §4.7.6.7 CM_05/_06. The DHCP-side
// expectations (DUT MAC, server identity, offered IP) come from the
// existing `Dhcpv4Expected`. The UDP-side expectations carry:
//
//   * `unused_routed_ip_be` — the spec's `<IP-UNUSED-ADDRESS>` literal,
//     which the harness pins at 192.168.99.42 (a different RFC 1918
//     subnet from the dev-netns 172.16.0.0/24). The DUT's post-BOUND
//     UDP egress MUST carry this dst_ip if the test is to verify
//     "DUT applied the gateway from Option 3".
//
//   * `router_mac` — the L2 MAC the gateway resolves to. The dev netns
//     pre-pins `<kDefaultServerIdBe, kTesterInjectedMac>` permanent
//     before the case starts (smoke-test.sh per-CM setup), so a valid
//     egress to IP-UNUSED-ADDRESS via gateway leaves the iface with
//     `kTesterInjectedMac` in eth_dst. Without this check a DUT that
//     stuffed eth_dst=broadcast or eth_dst=<own iface mac> would
//     spuriously pass the L3 predicate.
//
// Composition with `Dhcpv4Expected` (not inheritance) matches the
// `UdpAndDhcpv4Captured` shape — SCXML guards address each protocol's
// fields by their unprefixed names within the sub-context.
struct UdpAndDhcpv4Expected {
    Dhcpv4Expected dhcpv4{};

    std::uint32_t               unused_routed_ip_be =
        ::tc8::sce::dhcpv4::kUnusedRoutedIpBe;
    std::array<std::uint8_t, 6> router_mac          =
        ::tc8::stimulus::kTesterInjectedMac;
};

inline void applyTestConfig(UdpAndDhcpv4Expected &e, const TestConfig &cfg) {
    applyTestConfig(e.dhcpv4, cfg);
}

}  // namespace tc8
