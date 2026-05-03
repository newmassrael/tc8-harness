#pragma once

#include <string_view>

#include "sce_integration/case_registry.h"
#include "sce_integration/cases/_dhcpv4_traits_base.h"
#include "sce_integration/ipv4_linklocal_common.h"
#include "sce_integration/test_runner.h"

#include "dhcpv4_client_protocol_02_sm.h"

namespace tc8::sce::cases {

using Dhcpv4ClientProtocol02SM =
    ::SCE::Generated::dhcpv4_client_protocol_02::dhcpv4_client_protocol_02;

}  // namespace tc8::sce::cases

namespace tc8::sce {

template <>
struct TestCaseTraits<cases::Dhcpv4ClientProtocol02SM>
    : Dhcpv4AnyBase<cases::Dhcpv4ClientProtocol02SM> {
    static constexpr std::string_view kCaseId =
        "DHCPV4_CLIENT_PROTOCOL_02";
    static constexpr std::string_view kSpecSection = "4.7.6.2";
    static constexpr std::string_view kDescription =
        "DHCPDISCOVER carries Option 53 (DHCP message type) — every DHCP "
        "message MUST include this option (RFC 2131 §3, MUST)";
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
            case State::Fail_message_type_option_absent:
                return "fail:dut_dhcp_discover_missing_message_type_option";
            case State::Fail_timeout:
                return "fail:no_dut_dhcp_discover_within_listen_window";
            default:
                return "running";
        }
    }
};

}  // namespace tc8::sce

TC8_REGISTER_CASE(::tc8::sce::cases::Dhcpv4ClientProtocol02SM,
                  dhcpv4_client_protocol_02)
