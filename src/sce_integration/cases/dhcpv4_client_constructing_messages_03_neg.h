#pragma once

#include <string_view>

#include "tc8/upper_tester_protocol.h"

#include "sce_integration/case_registry.h"
#include "sce_integration/cases/_dhcpv4_traits_base.h"
#include "sce_integration/dhcpv4_pilot_common.h"
#include "sce_integration/test_runner.h"

#include "dhcpv4_client_constructing_messages_03_neg_sm.h"

namespace tc8::sce::cases {

using Dhcpv4ClientConstructingMessages03NegSM =
    ::SCE::Generated::dhcpv4_client_constructing_messages_03_neg::dhcpv4_client_constructing_messages_03_neg;

}  // namespace tc8::sce::cases

namespace tc8::sce {

template <>
struct TestCaseTraits<cases::Dhcpv4ClientConstructingMessages03NegSM>
    : Dhcpv4AnyBase<cases::Dhcpv4ClientConstructingMessages03NegSM> {
    static constexpr std::string_view kCaseId =
        "DHCPv4_CLIENT_CONSTRUCTING_MESSAGES_03_NEG";
    static constexpr std::string_view kDescription =
        "Self-validation of CONSTRUCTING_MESSAGES_03: tc8-dut's DHCP client "
        "sources its pre-binding DHCPDISCOVER from a non-zero IP address "
        "(RFC 2131 §4.1 requires src=0) via the DiscoverSrcNonzero firmware "
        "flavor. A conformant client (flavor None) uses src=0, so the "
        "negative's fail_compliant branch is the live conformant-DUT "
        "outcome.";

    static void stimulus(Captured& /*c*/,
                         const ::tc8::TestConfig& cfg,
                         std::string_view iface) {
        ::tc8::sce::dhcpv4::emitStartDhcpClientBuggy(
            cfg, iface, cfg.dut.mac,
            ::tc8::ut::kDhcpFlavorDiscoverSrcNonzero);
    }
};

}  // namespace tc8::sce

TC8_REGISTER_CASE(::tc8::sce::cases::Dhcpv4ClientConstructingMessages03NegSM,
                  dhcpv4_client_constructing_messages_03_neg)
