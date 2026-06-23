#pragma once

#include <string_view>

#include "sce_integration/case_registry.h"
#include "sce_integration/cases/_dhcpv4_traits_base.h"
#include "sce_integration/ipv4_linklocal_common.h"
#include "sce_integration/test_runner.h"

#include "dhcpv4_client_initialization_allocation_03_sm.h"

namespace tc8::sce::cases {

using Dhcpv4ClientInitializationAllocation03SM =
    ::SCE::Generated::dhcpv4_client_initialization_allocation_03::dhcpv4_client_initialization_allocation_03;

}  // namespace tc8::sce::cases

namespace tc8::sce {

template <>
struct TestCaseTraits<cases::Dhcpv4ClientInitializationAllocation03SM>
    : Dhcpv4AnyBase<cases::Dhcpv4ClientInitializationAllocation03SM> {
    static constexpr std::string_view kCaseId =
        "DHCPv4_CLIENT_INITIALIZATION_ALLOCATION_03";
    static constexpr std::string_view kDescription =
        "DHCPDISCOVER 'chaddr' field carries the DUT iface MAC — the "
        "DUT-side hardware address identifying the client (RFC 2131 "
        "§4.4.1, MUST)";
    static void stimulus(Captured& /*c*/,
                         const ::tc8::TestConfig& cfg,
                         std::string_view iface) {
        ::tc8::sce::linklocal::emitStartLLAutoconfFast(
            cfg, iface, cfg.dut.mac);
    }
};

}  // namespace tc8::sce

TC8_REGISTER_CASE(::tc8::sce::cases::Dhcpv4ClientInitializationAllocation03SM,
                  dhcpv4_client_initialization_allocation_03)
