#pragma once

#include <string_view>

#include "sce_integration/case_registry.h"
#include "sce_integration/cases/_dhcpv4_traits_base.h"
#include "sce_integration/dhcpv4_server_stimulus.h"
#include "sce_integration/test_runner.h"

#include "dhcpv4_client_summary_01_sm.h"

namespace tc8::sce::cases {

using Dhcpv4ClientSummary01SM =
    ::SCE::Generated::dhcpv4_client_summary_01::dhcpv4_client_summary_01;

}  // namespace tc8::sce::cases

namespace tc8::sce {

template <>
struct TestCaseTraits<cases::Dhcpv4ClientSummary01SM>
    : Dhcpv4AnyBase<cases::Dhcpv4ClientSummary01SM> {
    static constexpr std::string_view kCaseId =
        "DHCPv4_CLIENT_SUMMARY_01";
    static constexpr std::string_view kSpecSection = "4.7.6.1";
    static constexpr std::string_view kDescription =
        "DUT-side DHCPv4 client listens on UDP port 68 — full DISCOVER "
        "→ OFFER → REQUEST lifecycle observed (RFC 2131 §4.1, MUST)";
    // 4-arg stimulus: kick the tc8-dut DHCPv4 client lifecycle, then
    // register the OFFER state-entry observer on Listening_for_request.
    // The observer fires after the SCXML transitions on the captured
    // DUT DISCOVER, reads `c.xid` + `c.chaddr` (just-populated by the
    // dispatch helper), and emits a BOOTREPLY OFFER carrying the
    // server emul defaults. The DUT then transits to REQUESTING and
    // emits a DHCPREQUEST which the SCXML's second listening state
    // observes.
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

    static std::string_view verdictFor(State s) {
        switch (s) {
            case State::Pass:
                return "pass";
            case State::Fail_no_discover:
                return "fail:no_dut_dhcp_discover_within_listen_window";
            case State::Fail_no_request:
                return "fail:no_dut_dhcp_request_after_offer";
            default:
                return "running";
        }
    }
};

}  // namespace tc8::sce

TC8_REGISTER_CASE(::tc8::sce::cases::Dhcpv4ClientSummary01SM,
                  dhcpv4_client_summary_01)
