#pragma once

#include "arp_captured.h"
#include "dhcpv4_captured.h"
#include "test_config.h"

namespace tc8 {

// Cross-protocol Named Context for cases that observe BOTH ARP and
// DHCPv4 frames in one SCXML. Composition (not inheritance) avoids the
// `observed_ts_us` member ambiguity ArpCaptured + Dhcpv4Captured would
// otherwise produce, and lets SCXML guards address each protocol's
// fields by their unprefixed names within their respective sub-context:
//
//   <sce:context id="captured"
//                cpp:type="tc8::ArpAndDhcpv4Captured"
//                cpp:include="sce_integration/arp_and_dhcpv4_captured.h"/>
//
//   <transition event="dhcp_observed"
//               cond="cpp:captured.dhcpv4.is_dhcp_discover()
//                     and captured.dhcpv4.chaddr_matches_dut_mac(
//                                expected.dhcpv4.dut_iface_mac)"
//               .../>
//   <transition event="arp_observed"
//               cond="cpp:captured.arp.is_arp_probe()
//                     and captured.arp.target_proto_ip_in_link_local_prefix()"
//               .../>
//
// First consumer: §4.5.6.1 IPv4_AUTOCONF_INTRO_01 (RFC 3927 §1.9) —
// DUT must complete DHCP successfully AND must NOT fall back to LL
// probing after binding the routable lease. The two-protocol
// observation is the SCXML's only way to express both invariants.
struct ArpAndDhcpv4Captured {
    ArpCaptured     arp{};
    Dhcpv4Captured  dhcpv4{};
};

// ADL hook called by `TestRunner<SM>` at construction. No-op (both
// sub-contexts' `applyTestConfig` overloads are also no-ops because
// captured fields are wire-derived). The overload exists so the
// uniform `applyTestConfig(c, cfg)` call in TestRunner compiles for
// every Named Context type.
inline void applyTestConfig(ArpAndDhcpv4Captured & /*c*/,
                            const TestConfig & /*cfg*/) {
}

// Trace-recording hook (Evidence Export). Emits both sub-contexts in a
// nested object so a verdict-decider case-note shows ARP and DHCPv4
// fields side-by-side. Mirrors `UdpAndDhcpv4Captured`'s shape.
inline void appendCapturedJson(std::string &out, const ArpAndDhcpv4Captured &c) {
    out.append("{\"arp\":");
    appendCapturedJson(out, c.arp);
    out.append(",\"dhcpv4\":");
    appendCapturedJson(out, c.dhcpv4);
    out.append("}");
}

}  // namespace tc8
