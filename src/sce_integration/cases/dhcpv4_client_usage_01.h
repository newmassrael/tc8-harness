#pragma once

#include <string_view>

#include "sce_integration/case_registry.h"
#include "sce_integration/cases/_dhcpv4_traits_base.h"
#include "sce_integration/dhcpv4_default_endpoints.h"
#include "sce_integration/dhcpv4_server_stimulus.h"
#include "sce_integration/test_runner.h"

#include "dhcpv4_client_usage_01_sm.h"

namespace tc8::sce::cases {

using Dhcpv4ClientUsage01SM =
    ::SCE::Generated::dhcpv4_client_usage_01::dhcpv4_client_usage_01;

}  // namespace tc8::sce::cases

namespace tc8::sce {

template <>
struct TestCaseTraits<cases::Dhcpv4ClientUsage01SM>
    : Dhcpv4AnyBase<cases::Dhcpv4ClientUsage01SM> {
    static constexpr std::string_view kCaseId =
        "DHCPV4_CLIENT_USAGE_01";
    static constexpr std::string_view kSpecSection = "4.7.6.5";
    static constexpr std::string_view kDescription =
        "DUT with multiple network interfaces uses DHCP through each "
        "interface independently — DISCOVER#1 (DIface-0) and DISCOVER#2 "
        "(DIface-1) carry distinct chaddr values (RFC 2131 §3.6, MUST)";
    static constexpr int              kTopology   = 2;
    // 4-arg stimulus shape — the trait registers two state-entry
    // observers on s2 entry:
    //
    //   1. `snapshotDiscoverChaddr()` — copies the DISCOVER#1 chaddr
    //      first-6 bytes into `discover_chaddr_snapshot` so the s2
    //      transition guard can compare DISCOVER#2 against it.
    //
    //   2. `emitStartDhcpClient(iface_index=1)` — kicks the secondary
    //      `Dhcpv4Client` instance on tc8-dut. Skips
    //      `kDhcpv4PilotInitialWait` (already paid by the first call)
    //      so DISCOVER#2 lands within the 6 s s2 deadline; the second
    //      DUT instance binds AF_PACKET on the secondary iface
    //      (veth-dut2-W) within ~milliseconds.
    //
    // Stimulus injection rides the primary tester iface (DIface-0
    // peer) — tc8-dut's UT server binds INADDR_ANY, so the request
    // dispatches to instance 1 by the trailing `iface_index` byte
    // regardless of which iface the request arrived on.
    static void stimulus(Captured& c,
                         const ::tc8::TestConfig& cfg,
                         std::string_view iface,
                         IStimulusScheduler& scheduler) {
        ::tc8::sce::dhcpv4::emitStartDhcpClient(
            cfg, iface, cfg.arp.dut_real_mac,
            /*retry_count=*/1,
            /*retry_interval_ms=*/1000,
            /*nak_to_discover_min_ms=*/0,
            /*nak_to_discover_max_ms=*/0,
            /*arp_probe_listen_ms=*/0,
            /*decline_to_discover_min_ms=*/0,
            /*decline_to_discover_max_ms=*/0,
            /*retx_first_ms=*/0,
            /*retx_cap_ms=*/0,
            /*retx_jitter_ms=*/0,
            /*iface_index=*/0,
            /*apply_initial_wait=*/true);

        scheduler.scheduleAfterStateEntry(
            static_cast<int>(State::Listening_for_d1_discover),
            [&c]() { c.snapshotDiscoverChaddr(); });

        scheduler.scheduleAfterStateEntry(
            static_cast<int>(State::Listening_for_d1_discover),
            [&cfg, iface_copy = std::string(iface)]() {
                ::tc8::sce::dhcpv4::emitStartDhcpClient(
                    cfg, iface_copy, cfg.arp.dut_real_mac,
                    /*retry_count=*/1,
                    /*retry_interval_ms=*/1000,
                    /*nak_to_discover_min_ms=*/0,
                    /*nak_to_discover_max_ms=*/0,
                    /*arp_probe_listen_ms=*/0,
                    /*decline_to_discover_min_ms=*/0,
                    /*decline_to_discover_max_ms=*/0,
                    /*retx_first_ms=*/0,
                    /*retx_cap_ms=*/0,
                    /*retx_jitter_ms=*/0,
                    /*iface_index=*/1,
                    /*apply_initial_wait=*/false);
            });
    }

    static std::string_view verdictFor(State s) {
        switch (s) {
            case State::Pass:
                return "pass";
            case State::Fail_no_d0_discover:
                return "fail:no_dut_dhcp_discover_on_diface_0";
            case State::Fail_no_d1_discover:
                return "fail:no_dut_dhcp_discover_on_diface_1";
            case State::Fail_chaddr_collision:
                return "fail:diface_0_and_diface_1_share_same_chaddr";
            default:
                return "running";
        }
    }
};

}  // namespace tc8::sce

TC8_REGISTER_CASE(::tc8::sce::cases::Dhcpv4ClientUsage01SM,
                  dhcpv4_client_usage_01)
