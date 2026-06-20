#pragma once

#include <string_view>

#include "tc8/upper_tester_protocol.h"

#include "sce_integration/case_registry.h"
#include "sce_integration/cases/_dhcpv4_traits_base.h"
#include "sce_integration/dhcpv4_server_stimulus.h"
#include "sce_integration/test_runner.h"

#include "dhcpv4_client_allocating_05_neg_sm.h"

namespace tc8::sce::cases {

using Dhcpv4ClientAllocating05NegSM =
    ::SCE::Generated::dhcpv4_client_allocating_05_neg::dhcpv4_client_allocating_05_neg;

}  // namespace tc8::sce::cases

namespace tc8::sce {

template <>
struct TestCaseTraits<cases::Dhcpv4ClientAllocating05NegSM>
    : Dhcpv4AnyBase<cases::Dhcpv4ClientAllocating05NegSM> {
    static constexpr std::string_view kCaseId =
        "DHCPv4_CLIENT_ALLOCATING_05_NEG";
    static constexpr std::string_view kSpecSection = "4.7.6.3";
    static constexpr std::string_view kDescription =
        "Self-validation of ALLOCATING_05: tc8-dut unicasts the post-OFFER "
        "DHCPREQUEST instead of broadcasting (RFC 2131 §3.1 MUST) via the "
        "RequestDstUnicast firmware flavor. A conformant client (flavor "
        "None) broadcasts, so the negative's fail_compliant branch is the "
        "live conformant-DUT outcome.";

    static void stimulus(Captured& c,
                         const ::tc8::TestConfig& cfg,
                         std::string_view iface,
                         IStimulusScheduler& scheduler) {
        ::tc8::sce::dhcpv4::emitStartDhcpClientBuggy(
            cfg, iface, cfg.dut.mac,
            ::tc8::ut::kDhcpFlavorRequestDstUnicast);
        ::tc8::sce::dhcpv4::scheduleDhcpReplyOnStateEntry(
            scheduler, static_cast<int>(State::Listening_for_request),
            iface, c, /*message_type=*/2);
    }
};

}  // namespace tc8::sce

TC8_REGISTER_CASE(::tc8::sce::cases::Dhcpv4ClientAllocating05NegSM,
                  dhcpv4_client_allocating_05_neg)
