#pragma once

#include <string_view>
#include <chrono>
#include <thread>

#include "sce_integration/case_registry.h"
#include "sce_integration/cases/_arp_traits_base.h"
#include "sce_integration/test_runner.h"
#include "stimulus/arp_builder.h"
#include "stimulus/boot_timing.h"

#include "arp_49_sm.h"

namespace tc8::sce::cases {

using Arp49SM = ::SCE::Generated::arp_49::arp_49;

}  // namespace tc8::sce::cases

namespace tc8::sce {

template <>
struct TestCaseTraits<cases::Arp49SM>
    : ArpAndUdpBase<cases::Arp49SM> {
    static constexpr std::string_view kCaseId = "ARP_49";
    static constexpr std::string_view kDescription =
        "ARP cache entry ages out even when in use — DUT must re-ARP "
        "after timeout despite ongoing UDP egress traffic";
    // Blocking stimulus driving learn → UDP1 → UDP2 → ARP Request:
    //   1. Inject ARP Request (sender_hw=MAC1). Cache populated.
    //   2. UT req 1 (initial_wait 1500 ms) → DUT UDP with eth_dst=MAC1
    //      (~t=1.75 s; the 0x02 response + triggered datagram pair —
    //      the SCXML's wait_udp1/wait_udp2 may both be satisfied here,
    //      which still proves the spec's "in use" precondition).
    //   3+4. By conditioning strategy:
    //   * `arp.ut_cache_conditioning_s == 0` (Linux reference DUT,
    //     netns-sysctl-conditioned): cache has already gone STALE (max
    //     randomised base_reachable_time_ms = 749 ms < 1.75 s);
    //     UDP1's USE → DELAY. UT req 2 (initial_wait 500 ms) → more
    //     DUT UDP with eth_dst=MAC1 (~t=2.25 s) — USE keeps DELAY,
    //     lladdr remains. The final 2 s sleep covers the DELAY → PROBE
    //     transition (delay_first_probe_time=1): kernel emits the
    //     broadcast ARP Request at ~t=2.75 s. Wire-order invariant:
    //     every stimulus-driven UDP (≤ ~2.25 s) precedes the
    //     PROBE-fired Request (~2.75 s).
    //   * non-zero (UT-conditioned DUT, lwIP fixture): the spec's
    //     half-timeout waits (steps 8 + 12) compress to UT 0x17
    //     virtual aging. Age by half — the entry must SURVIVE (the
    //     "busy" axis: aging is on schedule, not eager) — then UT
    //     req 2 renders step 9's send and must still ride eth_dst=
    //     MAC1 (step-11 pass criterion). Age the remaining half —
    //     entry crosses the stack's timeout and is freed — then
    //     UT req 3 renders step 13's send: the DUT, finding no
    //     entry, emits the step-15 Request (RFC 826 queue-and-query;
    //     the 0x17 ACK's own egress may fire it even earlier).
    //
    // SCXML walks wait_udp1 → wait_udp2 → wait_arp_request → pass on
    // the {UDP1, UDP2, ARP} wire order under both strategies.
    static void stimulus(Captured & /*c*/, const ::tc8::TestConfig &cfg, std::string_view iface) {
        ::tc8::stimulus::emitArpLearningBoot(iface, cfg.arp.tester_ip, cfg.dut.ip,
                                             ::tc8::stimulus::ArpLearningVariant::Request);

        ::tc8::stimulus::BootTiming ut1;
        ut1.initial_wait = std::chrono::milliseconds(1500);
        ut1.retry_interval = std::chrono::milliseconds(0);
        ut1.total_emits = 1;
        emitArpEgressProvocation(cfg, iface, ut1);

        const std::uint16_t timeout_s = cfg.arp_stimulus.ut_cache_conditioning_s;
        const auto half = static_cast<std::uint16_t>(timeout_s / 2);
        const auto rest = static_cast<std::uint16_t>(timeout_s - half);
        if (timeout_s > 0) {
            // Step 8: half the timeout elapses — entry survives.
            std::this_thread::sleep_for(std::chrono::milliseconds(300));
            emitArpCacheConditioning(
                cfg, iface, ::tc8::ut::kArpConditionAgeBySeconds, half);
        }

        ::tc8::stimulus::BootTiming ut2;
        ut2.initial_wait = std::chrono::milliseconds(500);
        ut2.retry_interval = std::chrono::milliseconds(0);
        ut2.total_emits = 1;
        emitArpEgressProvocation(cfg, iface, ut2);

        if (timeout_s > 0) {
            // Step 12: the remaining half elapses — entry freed.
            std::this_thread::sleep_for(std::chrono::milliseconds(300));
            emitArpCacheConditioning(
                cfg, iface, ::tc8::ut::kArpConditionAgeBySeconds, rest);

            // Step 13: post-timeout egress → step-15 ARP Request.
            ::tc8::stimulus::BootTiming ut3;
            ut3.initial_wait = std::chrono::milliseconds(500);
            ut3.retry_interval = std::chrono::milliseconds(0);
            ut3.total_emits = 1;
            emitArpEgressProvocation(cfg, iface, ut3);

            std::this_thread::sleep_for(std::chrono::milliseconds(1000));
        } else {
            std::this_thread::sleep_for(std::chrono::milliseconds(2000));
        }
    }
};

}  // namespace tc8::sce

TC8_REGISTER_CASE(::tc8::sce::cases::Arp49SM, arp_49)
