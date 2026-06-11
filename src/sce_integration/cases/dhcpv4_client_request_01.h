#pragma once

#include <string_view>

#include "sce_integration/case_registry.h"
#include "sce_integration/cases/_dhcpv4_traits_base.h"
#include "sce_integration/dhcpv4_server_stimulus.h"
#include "sce_integration/test_runner.h"

#include "dhcpv4_client_request_01_sm.h"

namespace tc8::sce::cases {

using Dhcpv4ClientRequest01SM =
    ::SCE::Generated::dhcpv4_client_request_01::dhcpv4_client_request_01;

}  // namespace tc8::sce::cases

namespace tc8::sce {

template <>
struct TestCaseTraits<cases::Dhcpv4ClientRequest01SM>
    : Dhcpv4AnyBase<cases::Dhcpv4ClientRequest01SM> {
    static constexpr std::string_view kCaseId =
        "DHCPv4_CLIENT_REQUEST_01";
    static constexpr std::string_view kSpecSection = "4.7.6.8";
    static constexpr std::string_view kDescription =
        "DHCPREQUEST 'ciaddr' field is 0 in REQUESTING state — the address "
        "being requested is carried in Option 50, not the BOOTP fixed "
        "header (RFC 2131 §4.3.2, MUST)";
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
            case State::Fail_request_ciaddr_not_zero:
                return "fail:dut_dhcp_request_ciaddr_not_zero";
            default:
                return "running";
        }
    }
};

}  // namespace tc8::sce

TC8_REGISTER_CASE(::tc8::sce::cases::Dhcpv4ClientRequest01SM,
                  dhcpv4_client_request_01)
