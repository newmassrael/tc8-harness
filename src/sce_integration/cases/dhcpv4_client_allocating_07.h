#pragma once

#include <string_view>

#include "sce_integration/case_registry.h"
#include "sce_integration/cases/_dhcpv4_traits_base.h"
#include "sce_integration/dhcpv4_server_stimulus.h"
#include "sce_integration/test_runner.h"

#include "dhcpv4_client_allocating_07_sm.h"

namespace tc8::sce::cases {

using Dhcpv4ClientAllocating07SM =
    ::SCE::Generated::dhcpv4_client_allocating_07::dhcpv4_client_allocating_07;

}  // namespace tc8::sce::cases

namespace tc8::sce {

template <>
struct TestCaseTraits<cases::Dhcpv4ClientAllocating07SM>
    : Dhcpv4ArpBase<cases::Dhcpv4ClientAllocating07SM> {
    static constexpr std::string_view kCaseId =
        "DHCPv4_CLIENT_ALLOCATING_07";
    static constexpr std::string_view kSpecSection = "4.7.6.3";
    static constexpr std::string_view kDescription =
        "ARP-detected address-in-use → DHCPDECLINE + restart "
        "configuration process (DUT emits DISCOVER #2 after the DECLINE) "
        "(RFC 2131 §3.1, MUST)";
    // Topology 4 (STATIC-CLIENT-1 sharing the DIface-0 broadcast domain
    // with SERVER-1). Wire-level reduction: a single ARP Reply emitter
    // — same shape as INIT_ALLOC_09's `scheduleArpConflictReplyOnStateEntry`.
    static constexpr int              kTopology   = 4;
    static void stimulus(Captured& c,
                         const ::tc8::TestConfig& cfg,
                         std::string_view iface,
                         IStimulusScheduler& scheduler) {
        // ALLOCATING_07 only verifies the MUST behaviour (restart). Keep
        // `decline_to_discover_*` at the [0, 0] default so the DUT
        // restarts immediately after the DECLINE. ALLOCATING_08 opts in
        // to the [10000, 11000] ms window for the SHOULD-second-sentence
        // timing assert.
        ::tc8::sce::dhcpv4::emitStartDhcpClient(
            cfg, iface, cfg.dut.mac,
            /*retry_count=*/1,
            /*retry_interval_ms=*/1000,
            /*nak_to_discover_min_ms=*/0,
            /*nak_to_discover_max_ms=*/0,
            /*arp_probe_listen_ms=*/1500);
        ::tc8::sce::dhcpv4::scheduleDhcpReplyOnStateEntry(
            scheduler, static_cast<int>(State::Listening_for_first_request),
            iface, c.dhcpv4, /*message_type=*/2);
        ::tc8::sce::dhcpv4::scheduleDhcpReplyOnStateEntry(
            scheduler, static_cast<int>(State::Listening_for_arp_probe),
            iface, c.dhcpv4, /*message_type=*/5);
        // ARP conflict injection on listening_for_decline entry — fires
        // immediately after the DUT-emitted ARP Probe is observed,
        // triggering the DUT's listener to mark the address as in use.
        // Same MAC-UNUSED sentinel (02:00:DE:AD:00:01) as INIT_ALLOC_09.
        ::tc8::sce::dhcpv4::scheduleArpConflictReplyOnStateEntry(
            scheduler, static_cast<int>(State::Listening_for_decline),
            iface, cfg.dut.mac,
            ::tc8::sce::dhcpv4::kDefaultOfferedIpBe);
    }
};

}  // namespace tc8::sce

TC8_REGISTER_CASE(::tc8::sce::cases::Dhcpv4ClientAllocating07SM,
                  dhcpv4_client_allocating_07)
