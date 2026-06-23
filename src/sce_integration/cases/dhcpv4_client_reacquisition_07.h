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
    static constexpr std::string_view kDescription =
        "Lease expiration: DUT immediately stops network processing — "
        "no further DHCPREQUEST with the released ciaddr (RFC 2131 §4.4.5)";
    static void stimulus(Captured& c,
                         const ::tc8::TestConfig& cfg,
                         std::string_view iface,
                         IStimulusScheduler& scheduler) {
        ::tc8::sce::dhcpv4::emitStartDhcpClient(
            cfg, iface, cfg.dut.mac);
        // OFFER + ACK only — no T1/T2 reply, so RFC 2131 §4.4.5 lease
        // expiry trips the DUT runBoundPhaseMachine's lease_end branch
        // and INIT-restarts the lifecycle. The absence window in
        // state 5 (s5_deadline 3 s) observes the post-release UDP
        // silence on the spec-relevant ciaddr.
        ::tc8::sce::dhcpv4::scheduleRenewingFastEnvelopeReplies<SM>(
            scheduler, iface, c);
    }
};

}  // namespace tc8::sce

TC8_REGISTER_CASE(::tc8::sce::cases::Dhcpv4ClientReacquisition07SM,
                  dhcpv4_client_reacquisition_07)
