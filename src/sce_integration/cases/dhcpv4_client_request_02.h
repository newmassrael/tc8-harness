#pragma once

#include <string_view>

#include "sce_integration/case_registry.h"
#include "sce_integration/cases/_dhcpv4_traits_base.h"
#include "sce_integration/dhcpv4_server_stimulus.h"
#include "sce_integration/test_runner.h"

#include "dhcpv4_client_request_02_sm.h"

namespace tc8::sce::cases {

using Dhcpv4ClientRequest02SM =
    ::SCE::Generated::dhcpv4_client_request_02::dhcpv4_client_request_02;

}  // namespace tc8::sce::cases

namespace tc8::sce {

template <>
struct TestCaseTraits<cases::Dhcpv4ClientRequest02SM>
    : Dhcpv4AnyBase<cases::Dhcpv4ClientRequest02SM> {
    static constexpr std::string_view kCaseId =
        "DHCPv4_CLIENT_REQUEST_02";
    static constexpr std::string_view kDescription =
        "DHCPREQUEST advertises the offered IP via Option 50 (Requested IP "
        "Address) matching the OFFER yiaddr (RFC 2131 §4.3.2, MUST)";
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

TC8_REGISTER_CASE(::tc8::sce::cases::Dhcpv4ClientRequest02SM,
                  dhcpv4_client_request_02)
