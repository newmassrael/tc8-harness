#pragma once

#include <string_view>

#include "tc8/upper_tester_protocol.h"

#include "sce_integration/case_registry.h"
#include "sce_integration/cases/_dhcpv4_traits_base.h"
#include "sce_integration/dhcpv4_server_stimulus.h"
#include "sce_integration/test_runner.h"

#include "dhcpv4_client_reacquisition_01_neg_sm.h"

namespace tc8::sce::cases {

using Dhcpv4ClientReacquisition01NegSM =
    ::SCE::Generated::dhcpv4_client_reacquisition_01_neg::dhcpv4_client_reacquisition_01_neg;

}  // namespace tc8::sce::cases

namespace tc8::sce {

template <>
struct TestCaseTraits<cases::Dhcpv4ClientReacquisition01NegSM>
    : Dhcpv4AnyBase<cases::Dhcpv4ClientReacquisition01NegSM> {
    static constexpr std::string_view kCaseId =
        "DHCPv4_CLIENT_REACQUISITION_01_NEG";
    static constexpr std::string_view kSpecSection = "4.7.6.8";
    static constexpr std::string_view kDescription =
        "Self-validation of REACQUISITION_01: tc8-dut sends the RENEWING "
        "DHCPREQUEST to a wrong destination (RFC 2131 §4.4.5 mandates "
        "IP-unicast to the server-id) via the RenewingRequestDstWrong "
        "firmware flavor. A conformant client (flavor None) unicasts to "
        "the server-id, so the negative's fail_compliant branch is the "
        "live conformant-DUT outcome.";

    static void stimulus(Captured& c,
                         const ::tc8::TestConfig& cfg,
                         std::string_view iface,
                         IStimulusScheduler& scheduler) {
        ::tc8::sce::dhcpv4::emitStartDhcpClientBuggy(
            cfg, iface, cfg.dut.mac,
            ::tc8::ut::kDhcpFlavorRenewingRequestDstWrong);
        ::tc8::sce::dhcpv4::scheduleRenewingFastEnvelopeReplies<SM>(
            scheduler, iface, c);
    }
};

}  // namespace tc8::sce

TC8_REGISTER_CASE(::tc8::sce::cases::Dhcpv4ClientReacquisition01NegSM,
                  dhcpv4_client_reacquisition_01_neg)
