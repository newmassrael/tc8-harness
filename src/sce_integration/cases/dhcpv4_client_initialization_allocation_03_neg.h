#pragma once

#include <string_view>

#include "tc8/upper_tester_protocol.h"

#include "sce_integration/case_registry.h"
#include "sce_integration/cases/_dhcpv4_traits_base.h"
#include "sce_integration/dhcpv4_pilot_common.h"
#include "sce_integration/test_runner.h"

#include "dhcpv4_client_initialization_allocation_03_neg_sm.h"

namespace tc8::sce::cases {

using Dhcpv4ClientInitializationAllocation03NegSM =
    ::SCE::Generated::dhcpv4_client_initialization_allocation_03_neg::dhcpv4_client_initialization_allocation_03_neg;

}  // namespace tc8::sce::cases

namespace tc8::sce {

template <>
struct TestCaseTraits<cases::Dhcpv4ClientInitializationAllocation03NegSM>
    : Dhcpv4AnyBase<cases::Dhcpv4ClientInitializationAllocation03NegSM> {
    static constexpr std::string_view kCaseId =
        "DHCPv4_CLIENT_INITIALIZATION_ALLOCATION_03_NEG";
    static constexpr std::string_view kSpecSection = "4.7.6.9";
    static constexpr std::string_view kDescription =
        "Self-validation of INIT_ALLOC_03: tc8-dut flips a chaddr byte in its "
        "DHCPDISCOVER (RFC 2131 §4.4.1 MUST be the client MAC) via the "
        "DiscoverChaddrMismatch firmware flavor. A conformant client (flavor "
        "None) writes the matching chaddr, so the negative's fail_compliant "
        "branch is the live conformant-DUT outcome.";

    static void stimulus(Captured& /*c*/,
                         const ::tc8::TestConfig& cfg,
                         std::string_view iface) {
        ::tc8::sce::dhcpv4::emitStartDhcpClientBuggy(
            cfg, iface, cfg.dut.mac,
            ::tc8::ut::kDhcpFlavorDiscoverChaddrMismatch);
    }
};

}  // namespace tc8::sce

TC8_REGISTER_CASE(::tc8::sce::cases::Dhcpv4ClientInitializationAllocation03NegSM,
                  dhcpv4_client_initialization_allocation_03_neg)
