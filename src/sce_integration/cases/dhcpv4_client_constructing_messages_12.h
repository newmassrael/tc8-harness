#pragma once

#include <string_view>

#include "sce_integration/case_registry.h"
#include "sce_integration/cases/_dhcpv4_traits_base.h"
#include "sce_integration/test_runner.h"

#include "dhcpv4_client_constructing_messages_12_sm.h"

namespace tc8::sce::cases {

using Dhcpv4ClientConstructingMessages12SM =
    ::SCE::Generated::dhcpv4_client_constructing_messages_12::
        dhcpv4_client_constructing_messages_12;

}  // namespace tc8::sce::cases

namespace tc8::sce {

template <>
struct TestCaseTraits<cases::Dhcpv4ClientConstructingMessages12SM>
    : Dhcpv4AnyBase<cases::Dhcpv4ClientConstructingMessages12SM> {
    static constexpr std::string_view kCaseId =
        "DHCPv4_CLIENT_CONSTRUCTING_MESSAGES_12";
    static constexpr std::string_view kSpecSection = "4.7.6.7";
    static constexpr std::string_view kDescription =
        "DUT retransmits DHCPDISCOVER on doubling backoff capped at "
        "an upper bound (RFC 2131 §4.1, MUST). Fast-envelope cap = "
        "3200 ms; SCXML observes the cap-doubling fixpoint at the 6th "
        "DISCOVER.";
    // 3-arg stimulus: kick the lifecycle with retry_count=8 (enough for
    // SCXML to observe the cap interval at DISCOVER 6) and the fast-
    // envelope backoff knobs. Tester emits no OFFER, so the DUT runs
    // out the full retry budget on inter-DISCOVER waits.
    static void stimulus(Captured& /*c*/,
                         const ::tc8::TestConfig& cfg,
                         std::string_view iface) {
        ::tc8::sce::dhcpv4::emitStartDhcpClient(
            cfg, iface, cfg.dut.mac,
            /*retry_count=*/8U,
            /*retry_interval_ms=*/0U,
            /*nak_to_discover_min_ms=*/0U,
            /*nak_to_discover_max_ms=*/0U,
            /*arp_probe_listen_ms=*/0U,
            /*decline_to_discover_min_ms=*/0U,
            /*decline_to_discover_max_ms=*/0U,
            /*retx_first_ms=*/200U,
            /*retx_cap_ms=*/3200U,
            /*retx_jitter_ms=*/100U);
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
            case State::Fail_no_discover_4:
                return "fail:no_dut_dhcp_discover_4";
            case State::Fail_no_discover_5:
                return "fail:no_dut_dhcp_discover_5";
            case State::Fail_no_discover_6:
                return "fail:no_dut_dhcp_discover_6";
            case State::Fail_cap_exceeded:
                return "fail:dut_retx_interval_exceeds_cap";
            default:
                return "running";
        }
    }
};

}  // namespace tc8::sce

TC8_REGISTER_CASE(::tc8::sce::cases::Dhcpv4ClientConstructingMessages12SM,
                  dhcpv4_client_constructing_messages_12)
