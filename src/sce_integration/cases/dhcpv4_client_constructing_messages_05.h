#pragma once

#include <string_view>

#include "sce_integration/case_registry.h"
#include "sce_integration/cases/_dhcpv4_traits_base.h"
#include "sce_integration/cases/dhcpv4_router_option_egress_common.h"
#include "sce_integration/test_runner.h"

#include "dhcpv4_client_constructing_messages_05_sm.h"

namespace tc8::sce::cases {

using Dhcpv4ClientConstructingMessages05SM =
    ::SCE::Generated::dhcpv4_client_constructing_messages_05::
        dhcpv4_client_constructing_messages_05;

}  // namespace tc8::sce::cases

namespace tc8::sce {

template <>
struct TestCaseTraits<cases::Dhcpv4ClientConstructingMessages05SM>
    : Dhcpv4UdpBase<cases::Dhcpv4ClientConstructingMessages05SM> {
    static constexpr std::string_view kCaseId =
        "DHCPV4_CLIENT_CONSTRUCTING_MESSAGES_05";
    static constexpr std::string_view kSpecSection = "4.7.6.7";
    static constexpr std::string_view kDescription =
        "DUT parses Option Overload value=2 (sname holds options) and "
        "applies Option 3 (Router) so post-BOUND UDP egress to "
        "IP-UNUSED-ADDRESS uses the gateway as L2 next-hop "
        "(RFC 2132 §9.3 + RFC 2131 §3.5/§4.1, MUST)";
    static void stimulus(Captured& c,
                         const ::tc8::TestConfig& cfg,
                         std::string_view iface,
                         IStimulusScheduler& scheduler) {
        // CM_05: Option 52 = 2 → sname holds options. The same
        // Option 3 (Router) TLV mirrors onto OFFER and ACK so the
        // DUT extracts Router from whichever lifecycle reply it
        // sees first.
        cases::router_option_egress::wireRouterOverloadStimulus<SM>(
            c, cfg, iface, scheduler,
            /*option_52_overload=*/2U,
            /*sname_payload=*/cases::router_option_egress::buildOption3RouterPayload(),
            /*file_payload=*/{});
    }

    static std::string_view verdictFor(State s) {
        switch (s) {
            case State::Pass:
                return "pass";
            case State::Fail_no_discover:
                return "fail:no_dut_dhcp_discover_within_listen_window";
            case State::Fail_no_request:
                return "fail:no_dut_dhcp_request_after_offer";
            case State::Fail_no_dut_udp:
                return "fail:no_dut_udp_to_unused_routed_ip_via_router_option";
            default:
                return "running";
        }
    }
};

}  // namespace tc8::sce

TC8_REGISTER_CASE(::tc8::sce::cases::Dhcpv4ClientConstructingMessages05SM,
                  dhcpv4_client_constructing_messages_05)
