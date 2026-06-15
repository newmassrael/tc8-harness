#pragma once

#include <string_view>

#include "sce_integration/case_registry.h"
#include "sce_integration/cases/_dhcpv4_traits_base.h"
#include "sce_integration/ipv4_linklocal_common.h"
#include "sce_integration/test_runner.h"

#include "dhcpv4_client_constructing_messages_01_sm.h"

namespace tc8::sce::cases {

using Dhcpv4ClientConstructingMessages01SM =
    ::SCE::Generated::dhcpv4_client_constructing_messages_01::dhcpv4_client_constructing_messages_01;

}  // namespace tc8::sce::cases

namespace tc8::sce {

template <>
struct TestCaseTraits<cases::Dhcpv4ClientConstructingMessages01SM>
    : Dhcpv4AnyBase<cases::Dhcpv4ClientConstructingMessages01SM> {
    static constexpr std::string_view kCaseId =
        "DHCPv4_CLIENT_CONSTRUCTING_MESSAGES_01";
    static constexpr std::string_view kSpecSection = "4.7.6.7";
    static constexpr std::string_view kDescription =
        "DHCPDISCOVER options blob terminates on 0xFF (End Option) at "
        "position Last (RFC 2131 §4.1, MUST)";
    static void stimulus(Captured& /*c*/,
                         const ::tc8::TestConfig& cfg,
                         std::string_view iface) {
        ::tc8::sce::linklocal::emitStartLLAutoconfFast(
            cfg, iface, cfg.dut.mac);
    }
};

}  // namespace tc8::sce

TC8_REGISTER_CASE(::tc8::sce::cases::Dhcpv4ClientConstructingMessages01SM,
                  dhcpv4_client_constructing_messages_01)
