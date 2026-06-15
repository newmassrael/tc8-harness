#pragma once

#include <string_view>

#include "sce_integration/case_registry.h"
#include "sce_integration/cases/_dhcpv4_traits_base.h"
#include "sce_integration/dhcpv4_server_stimulus.h"
#include "sce_integration/test_runner.h"

#include "dhcpv4_client_constructing_messages_02_sm.h"

namespace tc8::sce::cases {

using Dhcpv4ClientConstructingMessages02SM =
    ::SCE::Generated::dhcpv4_client_constructing_messages_02::dhcpv4_client_constructing_messages_02;

}  // namespace tc8::sce::cases

namespace tc8::sce {

template <>
struct TestCaseTraits<cases::Dhcpv4ClientConstructingMessages02SM>
    : Dhcpv4AnyBase<cases::Dhcpv4ClientConstructingMessages02SM> {
    static constexpr std::string_view kCaseId =
        "DHCPv4_CLIENT_CONSTRUCTING_MESSAGES_02";
    static constexpr std::string_view kSpecSection = "4.7.6.7";
    static constexpr std::string_view kDescription =
        "DHCP clients MUST use the IP address provided in the 'server "
        "identifier' option for any unicast requests (RFC 2131 §4.1)";
    static void stimulus(Captured& c,
                         const ::tc8::TestConfig& cfg,
                         std::string_view iface,
                         IStimulusScheduler& scheduler) {
        ::tc8::sce::dhcpv4::emitStartDhcpClient(
            cfg, iface, cfg.dut.mac);
        ::tc8::sce::dhcpv4::scheduleRenewingFastEnvelopeReplies<SM>(
            scheduler, iface, c);
    }
};

}  // namespace tc8::sce

TC8_REGISTER_CASE(::tc8::sce::cases::Dhcpv4ClientConstructingMessages02SM,
                  dhcpv4_client_constructing_messages_02)
