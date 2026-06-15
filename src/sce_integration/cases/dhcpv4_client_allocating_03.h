#pragma once

#include <string_view>

#include "sce_integration/case_registry.h"
#include "sce_integration/cases/_dhcpv4_traits_base.h"
#include "sce_integration/dhcpv4_server_stimulus.h"
#include "sce_integration/test_runner.h"

#include "dhcpv4_client_allocating_03_sm.h"

namespace tc8::sce::cases {

using Dhcpv4ClientAllocating03SM =
    ::SCE::Generated::dhcpv4_client_allocating_03::dhcpv4_client_allocating_03;

}  // namespace tc8::sce::cases

namespace tc8::sce {

template <>
struct TestCaseTraits<cases::Dhcpv4ClientAllocating03SM>
    : Dhcpv4AnyBase<cases::Dhcpv4ClientAllocating03SM> {
    static constexpr std::string_view kCaseId =
        "DHCPv4_CLIENT_ALLOCATING_03";
    static constexpr std::string_view kSpecSection = "4.7.6.3";
    static constexpr std::string_view kDescription =
        "DHCPREQUEST includes Option 54 (Server Identifier) echoing the "
        "OFFER's server-id (RFC 2131 §3.1, MUST)";
    static void stimulus(Captured& c,
                         const ::tc8::TestConfig& cfg,
                         std::string_view iface,
                         IStimulusScheduler& scheduler) {
        ::tc8::sce::dhcpv4::emitStartDhcpClient(
            cfg, iface, cfg.dut.mac);
        ::tc8::sce::dhcpv4::scheduleDhcpReplyOnStateEntry(
            scheduler, static_cast<int>(State::Listening_for_request),
            iface, c, /*message_type=*/2);
    }
};

}  // namespace tc8::sce

TC8_REGISTER_CASE(::tc8::sce::cases::Dhcpv4ClientAllocating03SM,
                  dhcpv4_client_allocating_03)
