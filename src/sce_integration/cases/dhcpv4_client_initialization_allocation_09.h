#pragma once

#include <string_view>

#include "sce_integration/case_registry.h"
#include "sce_integration/cases/_dhcpv4_traits_base.h"
#include "sce_integration/dhcpv4_server_stimulus.h"
#include "sce_integration/test_runner.h"

#include "dhcpv4_client_initialization_allocation_09_sm.h"

namespace tc8::sce::cases {

using Dhcpv4ClientInitializationAllocation09SM =
    ::SCE::Generated::dhcpv4_client_initialization_allocation_09::dhcpv4_client_initialization_allocation_09;

}  // namespace tc8::sce::cases

namespace tc8::sce {

template <>
struct TestCaseTraits<cases::Dhcpv4ClientInitializationAllocation09SM>
    : Dhcpv4ArpBase<cases::Dhcpv4ClientInitializationAllocation09SM> {
    static constexpr std::string_view kCaseId =
        "DHCPv4_CLIENT_INITIALIZATION_ALLOCATION_09";
    static constexpr std::string_view kSpecSection = "4.7.6.9";
    static constexpr std::string_view kDescription =
        "Post-Probe ARP conflict triggers DHCPDECLINE emit (msg_type=4, "
        "ciaddr=0, Option 50=declined yiaddr, Option 54=server_id) "
        "(RFC 2131 §4.4.1 / §4.4.4, MUST)";
    static void stimulus(Captured& c,
                         const ::tc8::TestConfig& cfg,
                         std::string_view iface,
                         IStimulusScheduler& scheduler) {
        ::tc8::sce::dhcpv4::emitStartDhcpClient(
            cfg, iface, cfg.arp.dut_real_mac,
            /*retry_count=*/1,
            /*retry_interval_ms=*/1000,
            /*nak_to_discover_min_ms=*/0,
            /*nak_to_discover_max_ms=*/0,
            /*arp_probe_listen_ms=*/1500);
        ::tc8::sce::dhcpv4::scheduleDhcpReplyOnStateEntry(
            scheduler, static_cast<int>(State::Listening_for_first_request),
            iface, c.dhcpv4, /*message_type=*/2);
        ::tc8::sce::dhcpv4::scheduleDhcpReplyOnStateEntry(
            scheduler, static_cast<int>(State::Listening_for_arp_probe),
            iface, c.dhcpv4, /*message_type=*/5);
        // ARP conflict injection on listening_for_decline entry — fires
        // immediately after the DUT-emitted ARP Probe is observed,
        // triggering the DUT's listener to mark the address as in use.
        ::tc8::sce::dhcpv4::scheduleArpConflictReplyOnStateEntry(
            scheduler, static_cast<int>(State::Listening_for_decline),
            iface, cfg.arp.dut_real_mac,
            ::tc8::sce::dhcpv4::kDefaultOfferedIpBe);
    }

    static std::string_view verdictFor(State s) {
        switch (s) {
            case State::Pass:
                return "pass";
            case State::Fail_no_discover:
                return "fail:no_dut_dhcp_discover_within_listen_window";
            case State::Fail_no_request:
                return "fail:no_dut_dhcp_request_after_offer";
            case State::Fail_no_arp_probe:
                return "fail:no_dut_arp_probe_after_bound";
            case State::Fail_no_decline:
                return "fail:no_dut_dhcp_decline_after_arp_conflict";
            default:
                return "running";
        }
    }
};

}  // namespace tc8::sce

TC8_REGISTER_CASE(::tc8::sce::cases::Dhcpv4ClientInitializationAllocation09SM,
                  dhcpv4_client_initialization_allocation_09)
