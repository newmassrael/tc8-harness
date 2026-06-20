#pragma once

#include <string_view>

#include "tc8/upper_tester_protocol.h"

#include "sce_integration/case_registry.h"
#include "sce_integration/cases/_dhcpv4_traits_base.h"
#include "sce_integration/dhcpv4_server_stimulus.h"
#include "sce_integration/test_runner.h"

#include "dhcpv4_client_request_12_neg_sm.h"

namespace tc8::sce::cases {

using Dhcpv4ClientRequest12NegSM =
    ::SCE::Generated::dhcpv4_client_request_12_neg::dhcpv4_client_request_12_neg;

}  // namespace tc8::sce::cases

namespace tc8::sce {

template <>
struct TestCaseTraits<cases::Dhcpv4ClientRequest12NegSM>
    : Dhcpv4AnyBase<cases::Dhcpv4ClientRequest12NegSM> {
    static constexpr std::string_view kCaseId =
        "DHCPv4_CLIENT_REQUEST_12_NEG";
    static constexpr std::string_view kSpecSection = "4.7.6.8";
    static constexpr std::string_view kDescription =
        "Self-validation of REQUEST_12: tc8-dut unicasts the REBINDING "
        "DHCPREQUEST to a sentinel (RFC 2131 §4.4.5 mandates broadcast) via "
        "the RebindingDstUnicast firmware flavor. The sentinel is distinct "
        "from the server-id so the standalone SCXML tells a unicast "
        "REBINDING from a RENEWING retransmit. A conformant client (flavor "
        "None) broadcasts, so the negative's fail_compliant branch is the "
        "live conformant-DUT outcome.";

    static void stimulus(Captured& c,
                         const ::tc8::TestConfig& cfg,
                         std::string_view iface,
                         IStimulusScheduler& scheduler) {
        ::tc8::sce::dhcpv4::emitStartDhcpClientBuggy(
            cfg, iface, cfg.dut.mac,
            ::tc8::ut::kDhcpFlavorRebindingDstUnicast);
        ::tc8::sce::dhcpv4::scheduleRebindingFastEnvelopeReplies<SM>(
            scheduler, iface, c);
    }
};

}  // namespace tc8::sce

TC8_REGISTER_CASE(::tc8::sce::cases::Dhcpv4ClientRequest12NegSM,
                  dhcpv4_client_request_12_neg)
