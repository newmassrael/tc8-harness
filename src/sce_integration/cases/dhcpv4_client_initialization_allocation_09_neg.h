#pragma once

#include <string_view>

#include "tc8/upper_tester_protocol.h"

#include "sce_integration/case_registry.h"
#include "sce_integration/cases/_dhcpv4_traits_base.h"
#include "sce_integration/dhcpv4_server_stimulus.h"
#include "sce_integration/test_runner.h"

#include "dhcpv4_client_initialization_allocation_09_neg_sm.h"

namespace tc8::sce::cases {

using Dhcpv4ClientInitializationAllocation09NegSM =
    ::SCE::Generated::dhcpv4_client_initialization_allocation_09_neg::dhcpv4_client_initialization_allocation_09_neg;

}  // namespace tc8::sce::cases

namespace tc8::sce {

template <>
struct TestCaseTraits<cases::Dhcpv4ClientInitializationAllocation09NegSM>
    : Dhcpv4ArpBase<cases::Dhcpv4ClientInitializationAllocation09NegSM> {
    static constexpr std::string_view kCaseId =
        "DHCPv4_CLIENT_INITIALIZATION_ALLOCATION_09_NEG";
    static constexpr std::string_view kSpecSection = "4.7.6.9";
    static constexpr std::string_view kDescription =
        "Self-validation of INIT_ALLOC_09: on the injected ARP conflict, "
        "tc8-dut emits a DHCPDECLINE whose Option 50 carries a wrong address "
        "instead of the declined yiaddr (RFC 2131 §4.4.1 / table 5) via the "
        "DeclineRequestedIpWrong firmware flavor. A conformant client (flavor "
        "None) echoes the declined address, so the negative's fail_compliant "
        "branch is the live conformant-DUT outcome.";

    static void stimulus(Captured& c,
                         const ::tc8::TestConfig& cfg,
                         std::string_view iface,
                         IStimulusScheduler& scheduler) {
        ::tc8::sce::dhcpv4::emitStartDhcpClientBuggy(
            cfg, iface, cfg.dut.mac,
            ::tc8::ut::kDhcpFlavorDeclineRequestedIpWrong,
            /*apply_initial_wait=*/true,
            /*arp_probe_listen_ms=*/1500);
        ::tc8::sce::dhcpv4::scheduleDhcpReplyOnStateEntry(
            scheduler, static_cast<int>(State::Listening_for_first_request),
            iface, c.dhcpv4, /*message_type=*/2);
        ::tc8::sce::dhcpv4::scheduleDhcpReplyOnStateEntry(
            scheduler, static_cast<int>(State::Listening_for_arp_probe),
            iface, c.dhcpv4, /*message_type=*/5);
        // ARP conflict injection on listening_for_decline entry — mirrors the
        // positive _09: fires after the DUT's (conformant) ARP Probe so the
        // DUT's listener marks the address in use and emits the DHCPDECLINE,
        // which the flavor corrupts at Option 50.
        ::tc8::sce::dhcpv4::scheduleArpConflictReplyOnStateEntry(
            scheduler, static_cast<int>(State::Listening_for_decline),
            iface, cfg.dut.mac,
            ::tc8::sce::dhcpv4::kDefaultOfferedIpBe);
    }
};

}  // namespace tc8::sce

TC8_REGISTER_CASE(::tc8::sce::cases::Dhcpv4ClientInitializationAllocation09NegSM,
                  dhcpv4_client_initialization_allocation_09_neg)
