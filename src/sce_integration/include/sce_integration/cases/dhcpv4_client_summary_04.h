#pragma once

#include <string_view>

#include "sce_integration/case_registry.h"
#include "sce_integration/cases/_dhcpv4_traits_base.h"
#include "sce_integration/ipv4_linklocal_common.h"
#include "sce_integration/test_runner.h"

#include "dhcpv4_client_summary_04_sm.h"

namespace tc8::sce::cases {

using Dhcpv4ClientSummary04SM =
    ::SCE::Generated::dhcpv4_client_summary_04::dhcpv4_client_summary_04;

}  // namespace tc8::sce::cases

namespace tc8::sce {

template <>
struct TestCaseTraits<cases::Dhcpv4ClientSummary04SM>
    : Dhcpv4AnyBase<cases::Dhcpv4ClientSummary04SM> {
    static constexpr std::string_view kCaseId =
        "DHCPv4_CLIENT_SUMMARY_04";
    static constexpr std::string_view kDescription =
        "DHCPDISCOVER 'flags' field has reserved bits (1..15) set to 0 — "
        "RFC 2131 §2 Protocol Summary (MUST)";
    static void stimulus(Captured& /*c*/,
                         const ::tc8::TestConfig& cfg,
                         std::string_view iface) {
        ::tc8::sce::linklocal::emitStartLLAutoconfFast(
            cfg, iface, cfg.dut.mac);
    }
};

}  // namespace tc8::sce

TC8_REGISTER_CASE(::tc8::sce::cases::Dhcpv4ClientSummary04SM,
                  dhcpv4_client_summary_04)
