#pragma once

#include <string_view>

#include "sce_integration/case_registry.h"
#include "sce_integration/cases/_dhcpv4_traits_base.h"
#include "sce_integration/dhcpv4_server_stimulus.h"
#include "sce_integration/test_runner.h"

#include "dhcpv4_client_summary_02_sm.h"

namespace tc8::sce::cases {

using Dhcpv4ClientSummary02SM =
    ::SCE::Generated::dhcpv4_client_summary_02::dhcpv4_client_summary_02;

}  // namespace tc8::sce::cases

namespace tc8::sce {

template <>
struct TestCaseTraits<cases::Dhcpv4ClientSummary02SM>
    : Dhcpv4AnyBase<cases::Dhcpv4ClientSummary02SM> {
    static constexpr std::string_view kCaseId =
        "DHCPV4_CLIENT_SUMMARY_02";
    static constexpr std::string_view kSpecSection = "4.7.6.1";
    static constexpr std::string_view kDescription =
        "DUT discards DHCPOFFER with mismatched xid; selects the server "
        "whose OFFER xid matches the originating DHCPDISCOVER "
        "(RFC 2131 §4.3.1, MUST)";
    // Topology 3 in TC8 §4.7.3 is "1 DUT iface + 2 tester server
    // emuls on the same iface" — NOT multi-iface (USAGE_01's
    // Topology 2 is the only multi-iface §4.7 case). SUMMARY_02's
    // spec procedure (tc8_p221-p240.txt:482..501) routes both server
    // emuls through DIface-0; the harness mirrors this by scheduling
    // two state-entry observers on the single tester veth, each with
    // a distinct `server_id_be` (Option 54 echo = the spec's SERVER-1
    // / SERVER-2 disambiguator). Source IP also differs (`src_ip_be
    // = server_id_be` by builder convention), matching SERVER1-IP /
    // SERVER2-IP-ADDRESS in the procedure.
    static constexpr int              kTopology   = 3;
    // Two server emuls fire on Listening_for_request entry. SERVER-1
    // emits an OFFER with xid_offset = +1 (mismatched) — the DUT MUST
    // silently discard it. SERVER-2 emits an OFFER with xid_offset = 0
    // and a distinct server_id_be (`kSecondServerIdBe`) — the DUT
    // selects this server and the resulting REQUEST carries Option 54
    // = SERVER-2's identifier.
    static void stimulus(Captured& c,
                         const ::tc8::TestConfig& cfg,
                         std::string_view iface,
                         IStimulusScheduler& scheduler) {
        ::tc8::sce::dhcpv4::emitStartDhcpClient(
            cfg, iface, cfg.arp.dut_real_mac);

        ::tc8::sce::dhcpv4::ServerEmulParams server1{};
        server1.xid_offset = 1;
        ::tc8::sce::dhcpv4::scheduleDhcpReplyOnStateEntry(
            scheduler, static_cast<int>(State::Listening_for_request),
            iface, c, /*message_type=*/2, server1);

        ::tc8::sce::dhcpv4::ServerEmulParams server2{};
        server2.server_id_be = ::tc8::sce::dhcpv4::kSecondServerIdBe;
        ::tc8::sce::dhcpv4::scheduleDhcpReplyOnStateEntry(
            scheduler, static_cast<int>(State::Listening_for_request),
            iface, c, /*message_type=*/2, server2);
    }

    static std::string_view verdictFor(State s) {
        switch (s) {
            case State::Pass:
                return "pass";
            case State::Fail_no_discover:
                return "fail:no_dut_dhcp_discover_within_listen_window";
            case State::Fail_no_request:
                return "fail:no_dut_dhcp_request_after_offer";
            case State::Fail_request_selected_mismatched_server:
                return "fail:dut_dhcp_request_did_not_select_second_server";
            default:
                return "running";
        }
    }
};

}  // namespace tc8::sce

TC8_REGISTER_CASE(::tc8::sce::cases::Dhcpv4ClientSummary02SM,
                  dhcpv4_client_summary_02)
