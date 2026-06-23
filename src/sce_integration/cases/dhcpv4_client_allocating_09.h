#pragma once

#include <string_view>

#include "sce_integration/case_registry.h"
#include "sce_integration/cases/_dhcpv4_traits_base.h"
#include "sce_integration/dhcpv4_server_stimulus.h"
#include "sce_integration/test_runner.h"

#include "dhcpv4_client_allocating_09_sm.h"

namespace tc8::sce::cases {

using Dhcpv4ClientAllocating09SM =
    ::SCE::Generated::dhcpv4_client_allocating_09::dhcpv4_client_allocating_09;

}  // namespace tc8::sce::cases

namespace tc8::sce {

template <>
struct TestCaseTraits<cases::Dhcpv4ClientAllocating09SM>
    : Dhcpv4AnyBase<cases::Dhcpv4ClientAllocating09SM> {
    static constexpr std::string_view kCaseId =
        "DHCPv4_CLIENT_ALLOCATING_09";
    static constexpr std::string_view kDescription =
        "DHCPNAK received in RENEWING state restarts the configuration "
        "process (RFC 2131 §3.1)";
    static void stimulus(Captured& c,
                         const ::tc8::TestConfig& cfg,
                         std::string_view iface,
                         IStimulusScheduler& scheduler) {
        ::tc8::sce::dhcpv4::emitStartDhcpClient(
            cfg, iface, cfg.dut.mac);
        ::tc8::sce::dhcpv4::scheduleRenewingNakSchedule<SM>(
            scheduler, iface, c);
    }
};

}  // namespace tc8::sce

TC8_REGISTER_CASE(::tc8::sce::cases::Dhcpv4ClientAllocating09SM,
                  dhcpv4_client_allocating_09)
