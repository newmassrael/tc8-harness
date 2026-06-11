#pragma once

#include <string_view>

#include "sce_integration/case_registry.h"
#include "sce_integration/cases/_dhcpv4_traits_base.h"
#include "sce_integration/dhcpv4_server_stimulus.h"
#include "sce_integration/test_runner.h"

#include "dhcpv4_client_initialization_allocation_04_sm.h"

namespace tc8::sce::cases {

using Dhcpv4ClientInitializationAllocation04SM =
    ::SCE::Generated::dhcpv4_client_initialization_allocation_04::dhcpv4_client_initialization_allocation_04;

}  // namespace tc8::sce::cases

namespace tc8::sce {

template <>
struct TestCaseTraits<cases::Dhcpv4ClientInitializationAllocation04SM>
    : Dhcpv4AnyBase<cases::Dhcpv4ClientInitializationAllocation04SM> {
    static constexpr std::string_view kCaseId =
        "DHCPv4_CLIENT_INITIALIZATION_ALLOCATION_04";
    static constexpr std::string_view kSpecSection = "4.7.6.9";
    static constexpr std::string_view kDescription =
        "DUT silently discards DHCPOFFER with mismatched xid; does not "
        "emit DHCPREQUEST in response (RFC 2131 §4.4.1, MUST)";
    static void stimulus(Captured& c,
                         const ::tc8::TestConfig& cfg,
                         std::string_view iface,
                         IStimulusScheduler& scheduler) {
        ::tc8::sce::dhcpv4::emitStartDhcpClient(
            cfg, iface, cfg.dut.mac);
        ::tc8::sce::dhcpv4::ServerEmulParams mismatched{};
        mismatched.xid_offset = 1;
        ::tc8::sce::dhcpv4::scheduleDhcpReplyOnStateEntry(
            scheduler, static_cast<int>(State::Listening_for_no_request),
            iface, c, /*message_type=*/2, mismatched);
    }

    static std::string_view verdictFor(State s) {
        switch (s) {
            case State::Pass:
                return "pass";
            case State::Fail_unexpected_request:
                return "fail:dut_dhcp_request_after_mismatched_xid_offer";
            case State::Fail_no_discover:
                return "fail:no_dut_dhcp_discover_within_listen_window";
            default:
                return "running";
        }
    }
};

}  // namespace tc8::sce

TC8_REGISTER_CASE(::tc8::sce::cases::Dhcpv4ClientInitializationAllocation04SM,
                  dhcpv4_client_initialization_allocation_04)
