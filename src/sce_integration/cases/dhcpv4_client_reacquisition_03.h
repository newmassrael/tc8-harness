#pragma once

#include <string_view>

#include "sce_integration/case_registry.h"
#include "sce_integration/cases/_dhcpv4_traits_base.h"
#include "sce_integration/dhcpv4_server_stimulus.h"
#include "sce_integration/test_runner.h"

#include "dhcpv4_client_reacquisition_03_sm.h"

namespace tc8::sce::cases {

using Dhcpv4ClientReacquisition03SM =
    ::SCE::Generated::dhcpv4_client_reacquisition_03::dhcpv4_client_reacquisition_03;

}  // namespace tc8::sce::cases

namespace tc8::sce {

template <>
struct TestCaseTraits<cases::Dhcpv4ClientReacquisition03SM>
    : Dhcpv4AnyBase<cases::Dhcpv4ClientReacquisition03SM> {
    static constexpr std::string_view kCaseId =
        "DHCPv4_CLIENT_REACQUISITION_03";
    static constexpr std::string_view kSpecSection = "4.7.6.8";
    static constexpr std::string_view kDescription =
        "T1 = 0.5 × duration_of_lease: RENEWING REQUEST emitted within "
        "T1 ± ParamToleranceTime of the last DHCPACK (RFC 2131 §4.4.5)";
    static void stimulus(Captured& c,
                         const ::tc8::TestConfig& cfg,
                         std::string_view iface,
                         IStimulusScheduler& scheduler) {
        ::tc8::sce::dhcpv4::emitStartDhcpClient(
            cfg, iface, cfg.arp.dut_real_mac);
        ::tc8::sce::dhcpv4::scheduleRenewingFastEnvelopeReplies<SM>(
            scheduler, iface, c);
    }

    static std::string_view verdictFor(State s) {
        switch (s) {
            case State::Pass:
                return "pass";
            case State::Fail_no_discover:
                return "fail:no_dut_dhcp_discover_within_listen_window";
            case State::Fail_no_first_request:
                return "fail:no_dut_dhcp_request_after_offer";
            case State::Fail_no_renewing_request:
                return "fail:no_dut_renewing_request_within_listen_window";
            case State::Fail_renewing_request_t1_out_of_bounds:
                return "fail:dut_renewing_request_t1_interval_out_of_bounds";
            default:
                return "running";
        }
    }
};

}  // namespace tc8::sce

TC8_REGISTER_CASE(::tc8::sce::cases::Dhcpv4ClientReacquisition03SM,
                  dhcpv4_client_reacquisition_03)
