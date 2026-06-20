#pragma once

#include <string_view>

#include "tc8/upper_tester_protocol.h"

#include "sce_integration/case_registry.h"
#include "sce_integration/cases/_dhcpv4_traits_base.h"
#include "sce_integration/dhcpv4_pilot_common.h"
#include "sce_integration/test_runner.h"

#include "dhcpv4_client_allocating_01_neg_sm.h"

namespace tc8::sce::cases {

using Dhcpv4ClientAllocating01NegSM =
    ::SCE::Generated::dhcpv4_client_allocating_01_neg::dhcpv4_client_allocating_01_neg;

}  // namespace tc8::sce::cases

namespace tc8::sce {

template <>
struct TestCaseTraits<cases::Dhcpv4ClientAllocating01NegSM>
    : Dhcpv4AnyBase<cases::Dhcpv4ClientAllocating01NegSM> {
    static constexpr std::string_view kCaseId =
        "DHCPv4_CLIENT_ALLOCATING_01_NEG";
    static constexpr std::string_view kSpecSection = "4.7.6.3";
    static constexpr std::string_view kDescription =
        "Self-validation of ALLOCATING_01: tc8-dut's DHCP client unicasts "
        "its DHCPDISCOVER instead of broadcasting to 255.255.255.255 "
        "(RFC 2131 §3.1 MUST) via the DiscoverDstUnicast firmware flavor. "
        "A conformant client (flavor None) broadcasts, so the negative's "
        "fail_compliant branch is the live conformant-DUT outcome.";

    static void stimulus(Captured& /*c*/,
                         const ::tc8::TestConfig& cfg,
                         std::string_view iface) {
        ::tc8::sce::dhcpv4::emitStartDhcpClientBuggy(
            cfg, iface, cfg.dut.mac,
            ::tc8::ut::kDhcpFlavorDiscoverDstUnicast);
    }
};

}  // namespace tc8::sce

TC8_REGISTER_CASE(::tc8::sce::cases::Dhcpv4ClientAllocating01NegSM,
                  dhcpv4_client_allocating_01_neg)
