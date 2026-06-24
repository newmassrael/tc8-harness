#pragma once

#include <string_view>

#include "tc8/upper_tester_protocol.h"

#include "sce_integration/case_registry.h"
#include "sce_integration/cases/_dhcpv4_traits_base.h"
#include "sce_integration/dhcpv4_server_stimulus.h"
#include "sce_integration/test_runner.h"

#include "dhcpv4_client_reacquisition_05_neg_sm.h"

namespace tc8::sce::cases {

using Dhcpv4ClientReacquisition05NegSM =
    ::SCE::Generated::dhcpv4_client_reacquisition_05_neg::dhcpv4_client_reacquisition_05_neg;

}  // namespace tc8::sce::cases

namespace tc8::sce {

template <>
struct TestCaseTraits<cases::Dhcpv4ClientReacquisition05NegSM>
    : Dhcpv4AnyBase<cases::Dhcpv4ClientReacquisition05NegSM> {
    static constexpr std::string_view kCaseId =
        "DHCPv4_CLIENT_REACQUISITION_05_NEG";
    static constexpr std::string_view kDescription =
        "Self-validation of REACQUISITION_05: the "
        "kDhcpFlavorRenewingRetxNoDelay timing mutant collapses the RENEWING "
        "half-remaining backoff to 0, so the inter-RENEWING interval falls "
        "below the [1, 3] s window; a conformant client waits (T2-T1)/2 (RFC "
        "2131 §4.4.5).";

    static void stimulus(Captured& c,
                         const ::tc8::TestConfig& cfg,
                         std::string_view iface,
                         IStimulusScheduler& scheduler) {
        ::tc8::sce::dhcpv4::emitStartDhcpClientBuggy(
            cfg, iface, cfg.dut.mac,
            ::tc8::ut::kDhcpFlavorRenewingRetxNoDelay);
        ::tc8::sce::dhcpv4::scheduleRetxLeaseEnvelopeReplies<SM>(
            scheduler, iface, c);
    }
};

}  // namespace tc8::sce

TC8_REGISTER_CASE(::tc8::sce::cases::Dhcpv4ClientReacquisition05NegSM,
                  dhcpv4_client_reacquisition_05_neg)
