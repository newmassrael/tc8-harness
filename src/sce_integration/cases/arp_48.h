#pragma once

#include <string_view>
#include <chrono>
#include <thread>

#include "sce_integration/case_registry.h"
#include "sce_integration/cases/_arp_traits_base.h"
#include "sce_integration/test_runner.h"
#include "stimulus/arp_builder.h"
#include "stimulus/boot_timing.h"

#include "arp_48_sm.h"

namespace tc8::sce::cases {

using Arp48SM = ::SCE::Generated::arp_48::arp_48;

}  // namespace tc8::sce::cases

namespace tc8::sce {

template <>
struct TestCaseTraits<cases::Arp48SM>
    : ArpAndUdpBase<cases::Arp48SM> {
    static constexpr std::string_view kCaseId = "ARP_48";
    static constexpr std::string_view kSpecSection = "4.2.4.2";
    static constexpr std::string_view kDescription =
        "ARP cache entry ages out when idle — DUT must re-ARP on next "
        "egress after <DYNAMIC-ARP-CACHE-TIMEOUT> seconds of inactivity";
    // Blocking stimulus exercising the spec's learn → UDP1 →
    // cache-expiry → ARP-request flow:
    //   1. Inject ARP Request (sender_hw=MAC1) — DUT cache populated
    //      via RFC 826 §2.3 (spec step 3).
    //   2. UT 0x02 OpTriggerSendUdp → DUT UDP egress with eth_dst=MAC1
    //      (spec step 7).
    //   3. Cache expiry + the step-11 ARP Request, by conditioning
    //      strategy:
    //      * `arp.ut_cache_conditioning_s == 0` (Linux reference DUT,
    //        netns-sysctl-conditioned): per the smoke-test.sh per-case
    //        sysctls the entry has already gone REACHABLE → STALE
    //        (base_reachable_time_ms=500, max-randomised expiry
    //        749 ms < the ~1.75 s when stim1's UDP fires); the UDP1
    //        USE moves it to DELAY, and the 2 s sleep covers the
    //        kernel-spontaneous DELAY → PROBE Request
    //        (delay_first_probe_time=1). No second UT request — the
    //        PROBE is the observation.
    //      * non-zero (UT-conditioned DUT, lwIP fixture): UT 0x17
    //        ages the DUT's table past its own timeout — the spec's
    //        step-8 "TESTER waits <DYNAMIC-ARP-CACHE-TIMEOUT> +
    //        <ARP-TOLERANCE-TIME>" compressed to virtual time — then
    //        a second 0x02 renders step 9's "send an UDP Message"
    //        and the DUT, finding no entry, emits the step-11
    //        Request (RFC 826 queue-and-query). The 0x17 status ACK's
    //        own egress may fire that Request even earlier; either
    //        frame satisfies the SCXML guard.
    //
    // SCXML walks wait_udp1 → wait_arp_request → pass on the
    // {UDP1, ARP} wire pair under both strategies.
    static void stimulus(Captured & /*c*/, const ::tc8::TestConfig &cfg, std::string_view iface) {
        ::tc8::stimulus::emitArpLearningBoot(iface, cfg.arp.tester_ip, cfg.arp.dut_real_ip,
                                             ::tc8::stimulus::ArpLearningVariant::Request);

        ::tc8::stimulus::BootTiming ut_timing;
        ut_timing.initial_wait = std::chrono::milliseconds(1500);
        ut_timing.retry_interval = std::chrono::milliseconds(0);
        ut_timing.total_emits = 1;
        emitArpEgressProvocation(cfg, iface, ut_timing);

        if (cfg.arp.ut_cache_conditioning_s > 0) {
            // UDP1 wire-drain margin, then expire (aging by exactly
            // the timeout reaches the stack's `age >= timeout` free
            // condition) and provoke the post-timeout egress.
            std::this_thread::sleep_for(std::chrono::milliseconds(500));
            emitArpCacheConditioning(cfg, iface,
                                     ::tc8::ut::kArpConditionAgeBySeconds,
                                     cfg.arp.ut_cache_conditioning_s);

            ::tc8::stimulus::BootTiming ut2;
            ut2.initial_wait = std::chrono::milliseconds(500);
            ut2.retry_interval = std::chrono::milliseconds(0);
            ut2.total_emits = 1;
            emitArpEgressProvocation(cfg, iface, ut2);

            // ARP-Request drain before the SCXML deadline starts.
            std::this_thread::sleep_for(std::chrono::milliseconds(1000));
        } else {
            // Wait for DELAY → PROBE (delay_first_probe_time=1 s) plus
            // tc8-dut-jitter / scheduling margin.
            std::this_thread::sleep_for(std::chrono::milliseconds(2000));
        }
    }

    static std::string_view verdictFor(State s) {
        switch (s) {
        case State::Pass:
            return "pass";
        case State::Fail_udp1_wrong_eth_dst:
            return "fail:first_udp_eth_dst_not_learned_mac";
        case State::Fail_no_udp1:
            return "fail:no_first_udp_after_cache_learning";
        case State::Fail_no_arp_request_after_timeout:
            return "fail:no_dut_arp_request_after_cache_timeout";
        default:
            return "running";
        }
    }
};

}  // namespace tc8::sce

TC8_REGISTER_CASE(::tc8::sce::cases::Arp48SM, arp_48)
