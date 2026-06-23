#pragma once

#include <string_view>

#include "tc8/upper_tester_protocol.h"

#include "sce_integration/case_registry.h"
#include "sce_integration/cases/_dhcpv4_traits_base.h"
#include "sce_integration/dhcpv4_server_stimulus.h"
#include "sce_integration/test_runner.h"

#include "dhcpv4_client_initialization_allocation_10_neg_sm.h"

namespace tc8::sce::cases {

using Dhcpv4ClientInitializationAllocation10NegSM =
    ::SCE::Generated::dhcpv4_client_initialization_allocation_10_neg::dhcpv4_client_initialization_allocation_10_neg;

}  // namespace tc8::sce::cases

namespace tc8::sce {

template <>
struct TestCaseTraits<cases::Dhcpv4ClientInitializationAllocation10NegSM>
    : Dhcpv4ArpBase<cases::Dhcpv4ClientInitializationAllocation10NegSM> {
    static constexpr std::string_view kCaseId =
        "DHCPv4_CLIENT_INITIALIZATION_ALLOCATION_10_NEG";
    static constexpr std::string_view kDescription =
        "Self-validation of INIT_ALLOC_10: after the conflict-free Probe "
        "window, tc8-dut broadcasts a gratuitous ARP Announce whose sender IP "
        "is wrong instead of the committed yiaddr (RFC 2131 §4.4.1) via the "
        "AnnounceSenderIpWrong firmware flavor. A conformant client (flavor "
        "None) announces the committed IP, so the negative's fail_compliant "
        "branch is the live conformant-DUT outcome.";

    static void stimulus(Captured& c,
                         const ::tc8::TestConfig& cfg,
                         std::string_view iface,
                         IStimulusScheduler& scheduler) {
        ::tc8::sce::dhcpv4::emitStartDhcpClientBuggy(
            cfg, iface, cfg.dut.mac,
            ::tc8::ut::kDhcpFlavorAnnounceSenderIpWrong,
            /*apply_initial_wait=*/true,
            /*arp_probe_listen_ms=*/1500);
        ::tc8::sce::dhcpv4::scheduleDhcpReplyOnStateEntry(
            scheduler, static_cast<int>(State::Listening_for_first_request),
            iface, c.dhcpv4, /*message_type=*/2);
        ::tc8::sce::dhcpv4::scheduleDhcpReplyOnStateEntry(
            scheduler, static_cast<int>(State::Listening_for_arp_probe),
            iface, c.dhcpv4, /*message_type=*/5);
    }
};

}  // namespace tc8::sce

TC8_REGISTER_CASE(::tc8::sce::cases::Dhcpv4ClientInitializationAllocation10NegSM,
                  dhcpv4_client_initialization_allocation_10_neg)
