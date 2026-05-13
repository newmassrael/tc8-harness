#pragma once

#include <string_view>

#include "sce_integration/case_registry.h"
#include "sce_integration/cases/_dhcpv4_traits_base.h"
#include "sce_integration/dhcpv4_server_stimulus.h"
#include "sce_integration/test_runner.h"

#include "dhcpv4_client_reacquisition_07_sm.h"

namespace tc8::sce::cases {

using Dhcpv4ClientReacquisition07SM =
    ::SCE::Generated::dhcpv4_client_reacquisition_07::dhcpv4_client_reacquisition_07;

}  // namespace tc8::sce::cases

namespace tc8::sce {

template <>
struct TestCaseTraits<cases::Dhcpv4ClientReacquisition07SM>
    : Dhcpv4AnyBase<cases::Dhcpv4ClientReacquisition07SM> {
    static constexpr std::string_view kCaseId =
        "DHCPv4_CLIENT_REACQUISITION_07";
    static constexpr std::string_view kSpecSection = "4.7.6.8";
    static constexpr std::string_view kDescription =
        "Lease expiration: DUT immediately stops network processing — "
        "no further DHCPREQUEST with the released ciaddr (RFC 2131 §4.4.5)";
    static void stimulus(Captured& c,
                         const ::tc8::TestConfig& cfg,
                         std::string_view iface,
                         IStimulusScheduler& scheduler) {
        ::tc8::sce::dhcpv4::emitStartDhcpClient(
            cfg, iface, cfg.arp.dut_real_mac);
        // OFFER + ACK only — no T1/T2 reply, so RFC 2131 §4.4.5 lease
        // expiry trips the DUT runBoundPhaseMachine's lease_end branch
        // and INIT-restarts the lifecycle. The absence window in
        // state 5 (s5_deadline 3 s) observes the post-release UDP
        // silence on the spec-relevant ciaddr.
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
            case State::Fail_no_lease_release:
                return "fail:no_dut_lease_release_discover_after_lease_end";
            case State::Fail_dut_kept_released_ip:
                return "fail:dut_kept_released_ip_after_lease_expiry";
            default:
                return "running";
        }
    }
};

}  // namespace tc8::sce

TC8_REGISTER_CASE(::tc8::sce::cases::Dhcpv4ClientReacquisition07SM,
                  dhcpv4_client_reacquisition_07)
