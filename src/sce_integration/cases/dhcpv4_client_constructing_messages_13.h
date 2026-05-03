#pragma once

#include <string_view>

#include "sce_integration/case_registry.h"
#include "sce_integration/cases/_dhcpv4_traits_base.h"
#include "sce_integration/test_runner.h"

#include "dhcpv4_client_constructing_messages_13_sm.h"

namespace tc8::sce::cases {

using Dhcpv4ClientConstructingMessages13SM =
    ::SCE::Generated::dhcpv4_client_constructing_messages_13::
        dhcpv4_client_constructing_messages_13;

}  // namespace tc8::sce::cases

namespace tc8::sce {

template <>
struct TestCaseTraits<cases::Dhcpv4ClientConstructingMessages13SM>
    : Dhcpv4AnyBase<cases::Dhcpv4ClientConstructingMessages13SM> {
    static constexpr std::string_view kCaseId =
        "DHCPV4_CLIENT_CONSTRUCTING_MESSAGES_13";
    static constexpr std::string_view kSpecSection = "4.7.6.7";
    static constexpr std::string_view kDescription =
        "DUT uses randomized exponential backoff for DHCPDISCOVER "
        "retransmissions: first interval = 4 ± 1 s, second = 8 ± 1 s "
        "(RFC 2131 §4.1, SHOULD).";
    // Spec defaults — no fast-envelope compression. retry_count=4
    // gives the firmware enough budget for the 3 spec-asserted
    // DISCOVERs plus one trailing margin attempt (which the SCXML
    // ignores by reaching pass on the 3rd DISCOVER).
    static void stimulus(Captured& /*c*/,
                         const ::tc8::TestConfig& cfg,
                         std::string_view iface) {
        ::tc8::sce::dhcpv4::emitStartDhcpClient(
            cfg, iface, cfg.arp.dut_real_mac,
            /*retry_count=*/4U,
            /*retry_interval_ms=*/0U,
            /*nak_to_discover_min_ms=*/0U,
            /*nak_to_discover_max_ms=*/0U,
            /*arp_probe_listen_ms=*/0U,
            /*decline_to_discover_min_ms=*/0U,
            /*decline_to_discover_max_ms=*/0U,
            /*retx_first_ms=*/4000U,
            /*retx_cap_ms=*/64000U,
            /*retx_jitter_ms=*/1000U);
    }

    static std::string_view verdictFor(State s) {
        switch (s) {
            case State::Pass:
                return "pass";
            case State::Fail_no_discover:
                return "fail:no_dut_dhcp_discover_within_listen_window";
            case State::Fail_no_discover_2:
                return "fail:no_dut_dhcp_discover_2";
            case State::Fail_no_discover_3:
                return "fail:no_dut_dhcp_discover_3";
            case State::Fail_first_interval_out_of_range:
                return "fail:dut_first_retx_interval_out_of_range";
            case State::Fail_second_interval_out_of_range:
                return "fail:dut_second_retx_interval_out_of_range";
            default:
                return "running";
        }
    }
};

}  // namespace tc8::sce

TC8_REGISTER_CASE(::tc8::sce::cases::Dhcpv4ClientConstructingMessages13SM,
                  dhcpv4_client_constructing_messages_13)
