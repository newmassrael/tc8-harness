#pragma once

#include <string_view>

#include "sce_integration/case_registry.h"
#include "sce_integration/cases/_dhcpv4_traits_base.h"
#include "sce_integration/dhcpv4_server_stimulus.h"
#include "sce_integration/test_runner.h"

#include "dhcpv4_client_constructing_messages_04_sm.h"

namespace tc8::sce::cases {

using Dhcpv4ClientCm04SM =
    ::SCE::Generated::dhcpv4_client_constructing_messages_04::dhcpv4_client_constructing_messages_04;

}  // namespace tc8::sce::cases

namespace tc8::sce {

template <>
struct TestCaseTraits<cases::Dhcpv4ClientCm04SM>
    : Dhcpv4AnyBase<cases::Dhcpv4ClientCm04SM> {
    static constexpr std::string_view kCaseId =
        "DHCPv4_CLIENT_CONSTRUCTING_MESSAGES_04";
    static constexpr std::string_view kSpecSection = "4.7.6.7";
    static constexpr std::string_view kDescription =
        "DHCPREQUEST source IP address field is 0 in REQUESTING state "
        "(RFC 2131 §4.1, MUST)";
    static void stimulus(Captured& c,
                         const ::tc8::TestConfig& cfg,
                         std::string_view iface,
                         IStimulusScheduler& scheduler) {
        ::tc8::sce::dhcpv4::emitStartDhcpClient(
            cfg, iface, cfg.dut.mac);
        ::tc8::sce::dhcpv4::scheduleDhcpReplyOnStateEntry(
            scheduler, static_cast<int>(State::Listening_for_request),
            iface, c, /*message_type=*/2);
    }

    static std::string_view verdictFor(State s) {
        switch (s) {
            case State::Pass:
                return "pass";
            case State::Fail_no_discover:
                return "fail:no_dut_dhcp_discover_within_listen_window";
            case State::Fail_no_request:
                return "fail:no_dut_dhcp_request_after_offer";
            case State::Fail_request_src_ip_not_zero:
                return "fail:dut_dhcp_request_src_ip_not_zero";
            default:
                return "running";
        }
    }
};

}  // namespace tc8::sce

TC8_REGISTER_CASE(::tc8::sce::cases::Dhcpv4ClientCm04SM,
                  dhcpv4_client_constructing_messages_04)
