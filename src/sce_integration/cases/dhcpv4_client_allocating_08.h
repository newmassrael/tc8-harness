#pragma once

#include <string_view>

#include "sce_integration/case_registry.h"
#include "sce_integration/cases/_dhcpv4_traits_base.h"
#include "sce_integration/dhcpv4_server_stimulus.h"
#include "sce_integration/test_runner.h"

#include "dhcpv4_client_allocating_08_sm.h"

namespace tc8::sce::cases {

using Dhcpv4ClientAllocating08SM =
    ::SCE::Generated::dhcpv4_client_allocating_08::dhcpv4_client_allocating_08;

}  // namespace tc8::sce::cases

namespace tc8::sce {

template <>
struct TestCaseTraits<cases::Dhcpv4ClientAllocating08SM>
    : Dhcpv4ArpBase<cases::Dhcpv4ClientAllocating08SM> {
    static constexpr std::string_view kCaseId =
        "DHCPv4_CLIENT_ALLOCATING_08";
    static constexpr std::string_view kDescription =
        "After DHCPDECLINE the client SHOULD wait a minimum of ten "
        "seconds before restarting the configuration process — "
        "DECLINE→DISCOVER #2 interval > (10 - ParamToleranceTime) sec "
        "(RFC 2131 §3.1, SHOULD)";
    static constexpr int              kTopology   = 4;
    static void stimulus(Captured& c,
                         const ::tc8::TestConfig& cfg,
                         std::string_view iface,
                         IStimulusScheduler& scheduler) {
        // Opt into the [10000, 11000] ms post-DECLINE wait window so
        // the SCXML s5 cond's `decline_to_discover_within_us` lower
        // bound (9 s) succeeds. Spec says "minimum 10 s"; the window's
        // upper bound stays bounded so case_timeout=22 s still leaves
        // margin against worker jitter.
        ::tc8::sce::dhcpv4::emitStartDhcpClient(
            cfg, iface, cfg.dut.mac,
            /*retry_count=*/1,
            /*retry_interval_ms=*/1000,
            /*nak_to_discover_min_ms=*/0,
            /*nak_to_discover_max_ms=*/0,
            /*arp_probe_listen_ms=*/1500,
            /*decline_to_discover_min_ms=*/10000,
            /*decline_to_discover_max_ms=*/11000);
        ::tc8::sce::dhcpv4::scheduleDhcpReplyOnStateEntry(
            scheduler, static_cast<int>(State::Listening_for_first_request),
            iface, c.dhcpv4, /*message_type=*/2);
        ::tc8::sce::dhcpv4::scheduleDhcpReplyOnStateEntry(
            scheduler, static_cast<int>(State::Listening_for_arp_probe),
            iface, c.dhcpv4, /*message_type=*/5);
        ::tc8::sce::dhcpv4::scheduleArpConflictReplyOnStateEntry(
            scheduler, static_cast<int>(State::Listening_for_decline),
            iface, cfg.dut.mac,
            ::tc8::sce::dhcpv4::kDefaultOfferedIpBe);
    }
};

}  // namespace tc8::sce

TC8_REGISTER_CASE(::tc8::sce::cases::Dhcpv4ClientAllocating08SM,
                  dhcpv4_client_allocating_08)
