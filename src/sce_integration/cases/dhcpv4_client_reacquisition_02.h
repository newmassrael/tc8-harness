#pragma once

#include <string_view>

#include "sce_integration/case_registry.h"
#include "sce_integration/cases/_dhcpv4_traits_base.h"
#include "sce_integration/dhcpv4_server_stimulus.h"
#include "sce_integration/test_runner.h"

#include "dhcpv4_client_reacquisition_02_sm.h"

namespace tc8::sce::cases {

using Dhcpv4ClientReacquisition02SM =
    ::SCE::Generated::dhcpv4_client_reacquisition_02::dhcpv4_client_reacquisition_02;

}  // namespace tc8::sce::cases

namespace tc8::sce {

template <>
struct TestCaseTraits<cases::Dhcpv4ClientReacquisition02SM>
    : Dhcpv4AnyBase<cases::Dhcpv4ClientReacquisition02SM> {
    static constexpr std::string_view kCaseId =
        "DHCPv4_CLIENT_REACQUISITION_02";
    static constexpr std::string_view kSpecSection = "4.7.6.8";
    static constexpr std::string_view kDescription =
        "On DHCPACK timeout (T2) the client moves to REBINDING and "
        "broadcasts DHCPREQUEST to 0xffffffff (RFC 2131 §4.4.5)";
    static void stimulus(Captured& c,
                         const ::tc8::TestConfig& cfg,
                         std::string_view iface,
                         IStimulusScheduler& scheduler) {
        ::tc8::sce::dhcpv4::emitStartDhcpClient(
            cfg, iface, cfg.arp.dut_real_mac);
        ::tc8::sce::dhcpv4::scheduleRebindingFastEnvelopeReplies<SM>(
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
                return "fail:no_dut_renewing_request_after_ack";
            case State::Fail_no_rebinding_request:
                return "fail:no_dut_rebinding_request_within_listen_window";
            case State::Fail_rebinding_request_dst_not_broadcast:
                return "fail:dut_rebinding_request_dst_not_broadcast";
            default:
                return "running";
        }
    }
};

}  // namespace tc8::sce

TC8_REGISTER_CASE(::tc8::sce::cases::Dhcpv4ClientReacquisition02SM,
                  dhcpv4_client_reacquisition_02)
