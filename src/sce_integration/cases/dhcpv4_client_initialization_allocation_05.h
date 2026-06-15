#pragma once

#include <string_view>

#include "sce_integration/case_registry.h"
#include "sce_integration/cases/_dhcpv4_traits_base.h"
#include "sce_integration/dhcpv4_server_stimulus.h"
#include "sce_integration/test_runner.h"

#include "dhcpv4_client_initialization_allocation_05_sm.h"

namespace tc8::sce::cases {

using Dhcpv4ClientInitializationAllocation05SM =
    ::SCE::Generated::dhcpv4_client_initialization_allocation_05::dhcpv4_client_initialization_allocation_05;

}  // namespace tc8::sce::cases

namespace tc8::sce {

template <>
struct TestCaseTraits<cases::Dhcpv4ClientInitializationAllocation05SM>
    : Dhcpv4AnyBase<cases::Dhcpv4ClientInitializationAllocation05SM> {
    static constexpr std::string_view kCaseId =
        "DHCPv4_CLIENT_INITIALIZATION_ALLOCATION_05";
    static constexpr std::string_view kSpecSection = "4.7.6.9";
    static constexpr std::string_view kDescription =
        "DUT silently discards DHCPACK arriving in INIT phase (no "
        "preceding OFFER); does not emit DHCPREQUEST (RFC 2131 §4.4.1, "
        "MUST)";
    static void stimulus(Captured& c,
                         const ::tc8::TestConfig& cfg,
                         std::string_view iface,
                         IStimulusScheduler& scheduler) {
        ::tc8::sce::dhcpv4::emitStartDhcpClient(
            cfg, iface, cfg.dut.mac);
        ::tc8::sce::dhcpv4::scheduleDhcpReplyOnStateEntry(
            scheduler, static_cast<int>(State::Listening_for_no_request),
            iface, c, /*message_type=*/5);
    }
};

}  // namespace tc8::sce

TC8_REGISTER_CASE(::tc8::sce::cases::Dhcpv4ClientInitializationAllocation05SM,
                  dhcpv4_client_initialization_allocation_05)
