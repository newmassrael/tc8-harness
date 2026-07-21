#pragma once

#include <string_view>

#include "tc8/upper_tester_protocol.h"

#include "sce_integration/case_registry.h"
#include "sce_integration/cases/_dhcpv4_traits_base.h"
#include "sce_integration/dhcpv4_server_stimulus.h"
#include "sce_integration/test_runner.h"

#include "dhcpv4_client_reacquisition_04_neg_sm.h"

namespace tc8::sce::cases {

using Dhcpv4ClientReacquisition04NegSM =
    ::SCE::Generated::dhcpv4_client_reacquisition_04_neg::dhcpv4_client_reacquisition_04_neg;

}  // namespace tc8::sce::cases

namespace tc8::sce {

template <>
struct TestCaseTraits<cases::Dhcpv4ClientReacquisition04NegSM>
    : Dhcpv4AnyBase<cases::Dhcpv4ClientReacquisition04NegSM> {
    static constexpr std::string_view kCaseId =
        "DHCPv4_CLIENT_REACQUISITION_04_NEG";
    static constexpr std::string_view kDescription =
        "Self-validation of REACQUISITION_04: the "
        "kDhcpFlavorRebindingEntryEarly timing mutant collapses T2 onto T1, so "
        "the REBINDING DHCPREQUEST fires below the [4.25, 6.25] s window; a "
        "conformant client emits at T2 = lease*7/8 (RFC 2131 §4.4.5).";

    static void stimulus(Captured& c,
                         const ::tc8::TestConfig& cfg,
                         std::string_view iface,
                         IStimulusScheduler& scheduler) {
        ::tc8::sce::dhcpv4::emitStartDhcpClientBuggy(
            cfg, iface, cfg.dut.mac,
            ::tc8::ut::kDhcpFlavorRebindingEntryEarly);
        ::tc8::sce::dhcpv4::scheduleRebindingFastEnvelopeReplies<SM>(
            scheduler, iface, c);
    }
};

}  // namespace tc8::sce

TC8_REGISTER_CASE(::tc8::sce::cases::Dhcpv4ClientReacquisition04NegSM,
                  dhcpv4_client_reacquisition_04_neg)
