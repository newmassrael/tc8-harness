#pragma once

#include <string_view>

#include "tc8/upper_tester_protocol.h"

#include "sce_integration/case_registry.h"
#include "sce_integration/cases/_dhcpv4_traits_base.h"
#include "sce_integration/dhcpv4_pilot_common.h"
#include "sce_integration/test_runner.h"

#include "dhcpv4_client_summary_04_neg_sm.h"

namespace tc8::sce::cases {

using Dhcpv4ClientSummary04NegSM =
    ::SCE::Generated::dhcpv4_client_summary_04_neg::dhcpv4_client_summary_04_neg;

}  // namespace tc8::sce::cases

namespace tc8::sce {

template <>
struct TestCaseTraits<cases::Dhcpv4ClientSummary04NegSM>
    : Dhcpv4AnyBase<cases::Dhcpv4ClientSummary04NegSM> {
    static constexpr std::string_view kCaseId =
        "DHCPv4_CLIENT_SUMMARY_04_NEG";
    static constexpr std::string_view kSpecSection = "4.7.6.1";
    static constexpr std::string_view kDescription =
        "Self-validation of SUMMARY_04: tc8-dut's DHCP client emits a "
        "DHCPDISCOVER with a non-zero reserved 'flags' bit (RFC 2131 §2 "
        "MUST be zero) via the DiscoverReservedFlagsSet firmware flavor. "
        "A conformant client (flavor None) zeros the reserved bits, so the "
        "negative's fail_compliant branch is the live conformant-DUT "
        "outcome.";

    static void stimulus(Captured& /*c*/,
                         const ::tc8::TestConfig& cfg,
                         std::string_view iface) {
        ::tc8::sce::dhcpv4::emitStartDhcpClientBuggy(
            cfg, iface, cfg.dut.mac,
            ::tc8::ut::kDhcpFlavorDiscoverReservedFlagsSet);
    }
};

}  // namespace tc8::sce

TC8_REGISTER_CASE(::tc8::sce::cases::Dhcpv4ClientSummary04NegSM,
                  dhcpv4_client_summary_04_neg)
