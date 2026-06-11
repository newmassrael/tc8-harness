#pragma once

#include <string_view>

#include "sce_integration/case_registry.h"
#include "sce_integration/cases/_dhcpv4_traits_base.h"
#include "sce_integration/dhcpv4_server_stimulus.h"
#include "sce_integration/test_runner.h"

#include "dhcpv4_client_summary_03_sm.h"

namespace tc8::sce::cases {

using Dhcpv4ClientSummary03SM =
    ::SCE::Generated::dhcpv4_client_summary_03::dhcpv4_client_summary_03;

}  // namespace tc8::sce::cases

namespace tc8::sce {

template <>
struct TestCaseTraits<cases::Dhcpv4ClientSummary03SM>
    : Dhcpv4AnyBase<cases::Dhcpv4ClientSummary03SM> {
    static constexpr std::string_view kCaseId =
        "DHCPv4_CLIENT_SUMMARY_03";
    static constexpr std::string_view kSpecSection = "4.7.6.1";
    static constexpr std::string_view kDescription =
        "DUT ingests a 576-octet DHCPOFFER (RFC 791 minimum reassembly / "
        "RFC 2131 §2 maximum DHCP message size, MUST) and emits the "
        "resulting DHCPREQUEST";
    static void stimulus(Captured& c,
                         const ::tc8::TestConfig& cfg,
                         std::string_view iface,
                         IStimulusScheduler& scheduler) {
        ::tc8::sce::dhcpv4::emitStartDhcpClient(
            cfg, iface, cfg.dut.mac);
        ::tc8::sce::dhcpv4::ServerEmulParams params{};
        params.ip_datagram_total_bytes = 576;
        ::tc8::sce::dhcpv4::scheduleDhcpReplyOnStateEntry(
            scheduler, static_cast<int>(State::Listening_for_request),
            iface, c, /*message_type=*/2, params);
    }

    static std::string_view verdictFor(State s) {
        switch (s) {
            case State::Pass:
                return "pass";
            case State::Fail_no_discover:
                return "fail:no_dut_dhcp_discover_within_listen_window";
            case State::Fail_no_request:
                return "fail:no_dut_dhcp_request_after_padded_offer";
            default:
                return "running";
        }
    }
};

}  // namespace tc8::sce

TC8_REGISTER_CASE(::tc8::sce::cases::Dhcpv4ClientSummary03SM,
                  dhcpv4_client_summary_03)
