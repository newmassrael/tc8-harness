#pragma once

#include <string_view>

#include "sce_integration/case_registry.h"
#include "sce_integration/cases/_dhcpv4_traits_base.h"
#include "sce_integration/ipv4_linklocal_common.h"
#include "sce_integration/test_runner.h"

#include "dhcpv4_client_initialization_allocation_02_sm.h"

namespace tc8::sce::cases {

using Dhcpv4ClientInitializationAllocation02SM =
    ::SCE::Generated::dhcpv4_client_initialization_allocation_02::dhcpv4_client_initialization_allocation_02;

}  // namespace tc8::sce::cases

namespace tc8::sce {

template <>
struct TestCaseTraits<cases::Dhcpv4ClientInitializationAllocation02SM>
    : Dhcpv4AnyBase<cases::Dhcpv4ClientInitializationAllocation02SM> {
    static constexpr std::string_view kCaseId =
        "DHCPv4_CLIENT_INITIALIZATION_ALLOCATION_02";
    static constexpr std::string_view kSpecSection = "4.7.6.9";
    static constexpr std::string_view kDescription =
        "DHCPDISCOVER 'ciaddr' field is 0 in INIT state — the client has "
        "no bound address to advertise (RFC 2131 §4.4.1, MUST)";
    static void stimulus(Captured& /*c*/,
                         const ::tc8::TestConfig& cfg,
                         std::string_view iface) {
        ::tc8::sce::linklocal::emitStartLLAutoconfFast(
            cfg, iface, cfg.arp.dut_real_mac);
    }

    static std::string_view verdictFor(State s) {
        switch (s) {
            case State::Pass:
                return "pass";
            case State::Fail_ciaddr_nonzero:
                return "fail:dut_dhcp_discover_ciaddr_not_zero";
            case State::Fail_no_discover:
                return "fail:no_dut_dhcp_discover_within_listen_window";
            default:
                return "running";
        }
    }
};

}  // namespace tc8::sce

TC8_REGISTER_CASE(::tc8::sce::cases::Dhcpv4ClientInitializationAllocation02SM,
                  dhcpv4_client_initialization_allocation_02)
