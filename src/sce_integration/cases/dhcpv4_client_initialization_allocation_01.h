#pragma once

#include <string_view>

#include "sce_integration/case_registry.h"
#include "sce_integration/cases/_dhcpv4_traits_base.h"
#include "sce_integration/dhcpv4_server_stimulus.h"
#include "sce_integration/test_runner.h"

#include "dhcpv4_client_initialization_allocation_01_sm.h"

namespace tc8::sce::cases {

using Dhcpv4ClientInitializationAllocation01SM =
    ::SCE::Generated::dhcpv4_client_initialization_allocation_01::dhcpv4_client_initialization_allocation_01;

}  // namespace tc8::sce::cases

namespace tc8::sce {

template <>
struct TestCaseTraits<cases::Dhcpv4ClientInitializationAllocation01SM>
    : Dhcpv4AnyBase<cases::Dhcpv4ClientInitializationAllocation01SM> {
    static constexpr std::string_view kCaseId =
        "DHCPV4_CLIENT_INITIALIZATION_ALLOCATION_01";
    static constexpr std::string_view kSpecSection = "4.7.6.9";
    static constexpr std::string_view kDescription =
        "After NAK in RENEWING the DUT waits a random [1, 10] s before "
        "the restart DHCPDISCOVER (RFC 2131 §4.4.1, SHOULD)";
    static void stimulus(Captured& c,
                         const ::tc8::TestConfig& cfg,
                         std::string_view iface,
                         IStimulusScheduler& scheduler) {
        // §4.7.6.9 INIT_ALLOC_01: only this case opts into the
        // [1000, 10000] ms desync window so the DUT firmware applies
        // the spec-mandated random wait between NAK ingest and the
        // restart DISCOVER. Defaults preserved everywhere else
        // (instant restart per S6b precedent).
        ::tc8::sce::dhcpv4::emitStartDhcpClient(
            cfg, iface, cfg.arp.dut_real_mac,
            /*retry_count=*/1,
            /*retry_interval_ms=*/1000,
            /*nak_to_discover_min_ms=*/1000,
            /*nak_to_discover_max_ms=*/10000);
        // OFFER + ACK on the SELECTING-phase listening states (drives
        // DUT to BOUND) plus DHCPNAK on listening_for_second_discover
        // entry — the runBoundPhaseMachine NAK ingest path returns
        // INIT-restart, then runLoop applies the desync wait before
        // the next DHCPDISCOVER.
        ::tc8::sce::dhcpv4::scheduleRenewingNakSchedule<SM>(
            scheduler, iface, c);
    }

    static std::string_view verdictFor(State s) {
        switch (s) {
            case State::Pass:
                return "pass";
            case State::Fail_desync_out_of_range:
                return "fail:dut_dhcp_discover_nak_to_discover_outside_1_to_11_seconds";
            case State::Fail_no_discover:
                return "fail:no_dut_dhcp_discover_within_listen_window";
            case State::Fail_no_first_request:
                return "fail:no_dut_dhcp_request_after_offer";
            case State::Fail_no_renewing_request:
                return "fail:no_dut_renewing_request_within_listen_window";
            case State::Fail_no_second_discover:
                return "fail:no_dut_second_discover_after_init_return";
            default:
                return "running";
        }
    }
};

}  // namespace tc8::sce

TC8_REGISTER_CASE(::tc8::sce::cases::Dhcpv4ClientInitializationAllocation01SM,
                  dhcpv4_client_initialization_allocation_01)
