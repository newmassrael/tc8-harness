#pragma once

#include "dhcpv4_captured.h"
#include "test_config.h"
#include "udp_captured.h"

namespace tc8 {

// Cross-protocol Named Context for §4.7.6.7 CM_05/_06 — the DUT runs
// the full DHCPv4 lifecycle (DISCOVER → OFFER → REQUEST → ACK → BOUND)
// AND, post-BOUND, emits a UDP datagram to IP-UNUSED-ADDRESS through
// the gateway carried by the ACK's Option 3 (Router). The two
// observation surfaces (Dhcpv4Frame + UdpFrame) need distinct
// sub-contexts because the predicates and field ranges differ —
// composition (not inheritance) avoids the `observed_ts_us` member
// ambiguity a multi-inherited Captured would otherwise carry.
//
// Matching SCXML declaration:
//
//   <sce:context id="captured"
//                cpp:type="tc8::UdpAndDhcpv4Captured"
//                cpp:include="sce_integration/udp_and_dhcpv4_captured.h"/>
//
//   <transition event="dhcp_observed"
//               cond="cpp:captured.dhcpv4.is_dhcp_discover()
//                     and captured.dhcpv4.chaddr_matches_dut_mac(
//                                expected.dhcpv4.dut_iface_mac)"
//               .../>
//   <transition event="udp_observed"
//               cond="cpp:captured.udp.dst_ip == expected.unused_routed_ip_be
//                     and captured.udp.eth_dst == expected.router_mac"
//               .../>
struct UdpAndDhcpv4Captured {
    UdpCaptured     udp{};
    Dhcpv4Captured  dhcpv4{};
};

// ADL hook — both sub-contexts have no-op `applyTestConfig` overloads
// (their fields are wire-derived). Symmetric with `ArpAndDhcpv4Captured`.
inline void applyTestConfig(UdpAndDhcpv4Captured & /*c*/,
                            const TestConfig & /*cfg*/) {
}

}  // namespace tc8
