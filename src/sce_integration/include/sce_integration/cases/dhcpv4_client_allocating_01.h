#pragma once

#include <string_view>

#include "sce_integration/case_registry.h"
#include "sce_integration/cases/_dhcpv4_traits_base.h"
#include "sce_integration/ipv4_linklocal_common.h"
#include "sce_integration/test_runner.h"

#include "dhcpv4_client_allocating_01_sm.h"

namespace tc8::sce::cases {

using Dhcpv4ClientAllocating01SM =
    ::SCE::Generated::dhcpv4_client_allocating_01::dhcpv4_client_allocating_01;

}  // namespace tc8::sce::cases

namespace tc8::sce {

template <>
struct TestCaseTraits<cases::Dhcpv4ClientAllocating01SM>
    : Dhcpv4AnyBase<cases::Dhcpv4ClientAllocating01SM> {
    static constexpr std::string_view kCaseId =
        "DHCPv4_CLIENT_ALLOCATING_01";
    static constexpr std::string_view kDescription =
        "DHCPDISCOVER carries IPv4 destination = 255.255.255.255 limited "
        "broadcast (RFC 2131 §3.1, MUST)";
    static void stimulus(Captured& /*c*/,
                         const ::tc8::TestConfig& cfg,
                         std::string_view iface) {
        ::tc8::sce::linklocal::emitStartLLAutoconfFast(
            cfg, iface, cfg.dut.mac);
    }
};

}  // namespace tc8::sce

TC8_REGISTER_CASE(::tc8::sce::cases::Dhcpv4ClientAllocating01SM,
                  dhcpv4_client_allocating_01)
