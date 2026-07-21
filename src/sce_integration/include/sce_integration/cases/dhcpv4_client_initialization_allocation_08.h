#pragma once

#include <string_view>

#include "sce_integration/case_registry.h"
#include "sce_integration/cases/_dhcpv4_traits_base.h"
#include "sce_integration/dhcpv4_server_stimulus.h"
#include "sce_integration/test_runner.h"

#include "dhcpv4_client_initialization_allocation_08_sm.h"

namespace tc8::sce::cases {

using Dhcpv4ClientInitializationAllocation08SM =
    ::SCE::Generated::dhcpv4_client_initialization_allocation_08::dhcpv4_client_initialization_allocation_08;

}  // namespace tc8::sce::cases

namespace tc8::sce {

template <>
struct TestCaseTraits<cases::Dhcpv4ClientInitializationAllocation08SM>
    : Dhcpv4ArpBase<cases::Dhcpv4ClientInitializationAllocation08SM> {
    static constexpr std::string_view kCaseId =
        "DHCPv4_CLIENT_INITIALIZATION_ALLOCATION_08";
    static constexpr std::string_view kDescription =
        "Post-BOUND DUT emits ARP Probe with sender_ip=0, target_ip=offered "
        "yiaddr to verify the offered address is not in use (RFC 2131 §4.4.1)";
    static void stimulus(Captured& c,
                         const ::tc8::TestConfig& cfg,
                         std::string_view iface,
                         IStimulusScheduler& scheduler) {
        // Opt into the post-BOUND ARP Probe firmware path with a 1500 ms
        // listen window — fast envelope shrink of the 10 s spec
        // ParamListenTime (Q4 decision).
        ::tc8::sce::dhcpv4::Dhcpv4StartConfig sc;
        sc.arp_probe_listen_ms = 1500;
        ::tc8::sce::dhcpv4::emitStartDhcpClient(cfg, iface, cfg.dut.mac, sc);
        ::tc8::sce::dhcpv4::scheduleDhcpReplyOnStateEntry(
            scheduler, static_cast<int>(State::Listening_for_first_request),
            iface, c.dhcpv4, /*message_type=*/2);
        ::tc8::sce::dhcpv4::scheduleDhcpReplyOnStateEntry(
            scheduler, static_cast<int>(State::Listening_for_arp_probe),
            iface, c.dhcpv4, /*message_type=*/5);
    }
};

}  // namespace tc8::sce

TC8_REGISTER_CASE(::tc8::sce::cases::Dhcpv4ClientInitializationAllocation08SM,
                  dhcpv4_client_initialization_allocation_08)
