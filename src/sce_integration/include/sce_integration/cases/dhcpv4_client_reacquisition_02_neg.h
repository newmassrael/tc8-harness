#pragma once

#include <string_view>

#include "tc8/upper_tester_protocol.h"

#include "sce_integration/case_registry.h"
#include "sce_integration/cases/_dhcpv4_traits_base.h"
#include "sce_integration/dhcpv4_server_stimulus.h"
#include "sce_integration/test_runner.h"

#include "dhcpv4_client_reacquisition_02_neg_sm.h"

namespace tc8::sce::cases {

using Dhcpv4ClientReacquisition02NegSM =
    ::SCE::Generated::dhcpv4_client_reacquisition_02_neg::dhcpv4_client_reacquisition_02_neg;

}  // namespace tc8::sce::cases

namespace tc8::sce {

template <>
struct TestCaseTraits<cases::Dhcpv4ClientReacquisition02NegSM>
    : Dhcpv4AnyBase<cases::Dhcpv4ClientReacquisition02NegSM> {
    static constexpr std::string_view kCaseId =
        "DHCPv4_CLIENT_REACQUISITION_02_NEG";
    static constexpr std::string_view kDescription =
        "Self-validation of REACQUISITION_02: the kDhcpFlavorRebindingDstUnicast "
        "firmware flavor sends the REBINDING DHCPREQUEST to a unicast sentinel; a "
        "conformant client broadcasts it (RFC 2131 §4.4.5). Same invariant + mutant "
        "as REQUEST_12_NEG (shared template).";

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

TC8_REGISTER_CASE(::tc8::sce::cases::Dhcpv4ClientReacquisition02NegSM,
                  dhcpv4_client_reacquisition_02_neg)
