#pragma once

#include <string_view>

#include "tc8/upper_tester_protocol.h"

#include "sce_integration/case_registry.h"
#include "sce_integration/cases/_dhcpv4_traits_base.h"
#include "sce_integration/dhcpv4_server_stimulus.h"
#include "sce_integration/test_runner.h"

#include "dhcpv4_client_request_08_neg_sm.h"

namespace tc8::sce::cases {

using Dhcpv4ClientRequest08NegSM =
    ::SCE::Generated::dhcpv4_client_request_08_neg::dhcpv4_client_request_08_neg;

}  // namespace tc8::sce::cases

namespace tc8::sce {

template <>
struct TestCaseTraits<cases::Dhcpv4ClientRequest08NegSM>
    : Dhcpv4AnyBase<cases::Dhcpv4ClientRequest08NegSM> {
    static constexpr std::string_view kCaseId =
        "DHCPv4_CLIENT_REQUEST_08_NEG";
    static constexpr std::string_view kDescription =
        "Self-validation of REQUEST_08: tc8-dut writes a wrong 'ciaddr' in "
        "the RENEWING DHCPREQUEST (RFC 2131 §4.4.5 mandates the bound IP) "
        "via the ReacqRequestCiaddrWrong firmware flavor. A conformant "
        "client (flavor None) sets ciaddr to the bound IP, so the "
        "negative's fail_compliant branch is the live conformant-DUT "
        "outcome.";

    static void stimulus(Captured& c,
                         const ::tc8::TestConfig& cfg,
                         std::string_view iface,
                         IStimulusScheduler& scheduler) {
        ::tc8::sce::dhcpv4::emitStartDhcpClientBuggy(
            cfg, iface, cfg.dut.mac,
            ::tc8::ut::kDhcpFlavorReacqRequestCiaddrWrong);
        ::tc8::sce::dhcpv4::scheduleRenewingFastEnvelopeReplies<SM>(
            scheduler, iface, c);
    }
};

}  // namespace tc8::sce

TC8_REGISTER_CASE(::tc8::sce::cases::Dhcpv4ClientRequest08NegSM,
                  dhcpv4_client_request_08_neg)
