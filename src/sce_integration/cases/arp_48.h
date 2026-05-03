#pragma once

#include <string_view>
#include <chrono>
#include <thread>

#include "sce_integration/case_registry.h"
#include "sce_integration/cases/_arp_traits_base.h"
#include "sce_integration/test_runner.h"
#include "stimulus/arp_builder.h"
#include "stimulus/someip_sd_builder.h"

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
    // Three-phase blocking stimulus exercising the spec's learn → UDP1
    // → cache-expiry → ARP-request flow:
    //   1. Inject ARP Request (sender_hw=MAC1) — DUT cache populated
    //      REACHABLE via RFC 826 §2.3 (spec step 3).
    //   2. Subscribe → DUT UDP egress with eth_dst=MAC1 (spec step 7).
    //      Per the smoke-test.sh per-case sysctls, the entry has
    //      already transitioned REACHABLE → STALE (base_reachable_time
    //      ms=500, max-randomised expiry 749 ms, well before the
    //      ~1.75 s when stim1's UDP fires). DUT USE moves it to DELAY.
    //   3. 3 s sleep covers the DELAY → PROBE transition
    //      (delay_first_probe_time=1) and the resulting broadcast ARP
    //      Request (ucast_solicit=0 skips the unicast probe path).
    //
    // No second Subscribe — the kernel-spontaneous PROBE is the
    // ARP-Request observation; stim2 would be redundant and only adds
    // post-stimulus drain noise. SCXML walks wait_udp1 →
    // wait_arp_request → pass on the {UDP1, ARP} wire pair.
    static void stimulus(Captured & /*c*/, const ::tc8::TestConfig &cfg, std::string_view iface) {
        ::tc8::stimulus::emitArpLearningBoot(iface, cfg.arp.tester_ip, cfg.arp.dut_real_ip,
                                             ::tc8::stimulus::ArpLearningVariant::Request);

        ::tc8::stimulus::SdBootTiming sub_timing;
        sub_timing.initial_wait = std::chrono::milliseconds(1500);
        sub_timing.retry_interval = std::chrono::milliseconds(0);
        sub_timing.total_emits = 1;
        ::tc8::stimulus::emitSubscribeEventgroupBoot(iface, ::tc8::stimulus::SubscribeEventgroupTarget{}, sub_timing);

        // Wait for DELAY → PROBE (delay_first_probe_time=1 s) plus
        // tc8-dut-jitter / scheduling margin.
        std::this_thread::sleep_for(std::chrono::milliseconds(2000));
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
