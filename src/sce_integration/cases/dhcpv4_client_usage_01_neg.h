#pragma once

#include <string>
#include <string_view>

#include "tc8/upper_tester_protocol.h"

#include "sce_integration/case_registry.h"
#include "sce_integration/cases/_dhcpv4_traits_base.h"
#include "sce_integration/dhcpv4_default_endpoints.h"
#include "sce_integration/dhcpv4_server_stimulus.h"
#include "sce_integration/test_runner.h"

#include "dhcpv4_client_usage_01_neg_sm.h"

namespace tc8::sce::cases {

using Dhcpv4ClientUsage01NegSM =
    ::SCE::Generated::dhcpv4_client_usage_01_neg::dhcpv4_client_usage_01_neg;

}  // namespace tc8::sce::cases

namespace tc8::sce {

template <>
struct TestCaseTraits<cases::Dhcpv4ClientUsage01NegSM>
    : Dhcpv4AnyBase<cases::Dhcpv4ClientUsage01NegSM> {
    static constexpr std::string_view kCaseId =
        "DHCPv4_CLIENT_USAGE_01_NEG";
    static constexpr std::string_view kDescription =
        "Self-validation of USAGE_01: the kDhcpFlavorShareChaddrAcrossIface "
        "firmware flavor makes the secondary-iface client reuse iface-0's MAC "
        "as its DHCP chaddr (collision); a conformant client uses each iface's "
        "own MAC (RFC 2131 §3.6)";
    static constexpr int kTopology = 2;

    // Same Topology 2 lifecycle as the positive: iface-0 client (conformant)
    // at start, then on s2 entry snapshot DISCOVER#1's chaddr + kick the
    // iface-1 client. The divergence is the trailing flavor byte on the
    // iface-1 start — kDhcpFlavorShareChaddrAcrossIface arms the chaddr reuse,
    // so DISCOVER#2 carries iface-0's chaddr (collision). iface-0 stays
    // conformant so DISCOVER#1 + s1's chaddr_matches_dut_mac gate hold.
    static void stimulus(Captured& c,
                         const ::tc8::TestConfig& cfg,
                         std::string_view iface,
                         IStimulusScheduler& scheduler) {
        ::tc8::sce::dhcpv4::emitStartDhcpClient(
            cfg, iface, cfg.dut.mac,
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
                    cfg, iface_copy, cfg.dut.mac,
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
                    /*apply_initial_wait=*/false,
                    /*flavor=*/::tc8::ut::kDhcpFlavorShareChaddrAcrossIface);
            });
    }
};

}  // namespace tc8::sce

TC8_REGISTER_CASE(::tc8::sce::cases::Dhcpv4ClientUsage01NegSM,
                  dhcpv4_client_usage_01_neg)
