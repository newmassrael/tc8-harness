#pragma once

#include <string_view>
#include <chrono>
#include <thread>

#include "sce_integration/case_registry.h"
#include "sce_integration/cases/_arp_traits_base.h"
#include "sce_integration/test_runner.h"
#include "stimulus/arp_builder.h"
#include "stimulus/someip_sd_builder.h"

#include "arp_49_sm.h"

namespace tc8::sce::cases {

using Arp49SM = ::SCE::Generated::arp_49::arp_49;

}  // namespace tc8::sce::cases

namespace tc8::sce {

template <>
struct TestCaseTraits<cases::Arp49SM>
    : ArpAndUdpBase<cases::Arp49SM> {
    static constexpr std::string_view kCaseId = "ARP_49";
    static constexpr std::string_view kSpecSection = "4.2.4.2";
    static constexpr std::string_view kDescription =
        "ARP cache entry ages out even when in use — DUT must re-ARP "
        "after timeout despite ongoing UDP egress traffic";
    // Four-phase blocking stimulus driving learn → UDP1 → UDP2 →
    // (DELAY-timer-fired ARP Request):
    //   1. Inject ARP Request (sender_hw=MAC1). Cache REACHABLE.
    //   2. Sub1 (initial_wait 1500 ms) → DUT UDP1 with eth_dst=MAC1
    //      (~t=1.75 s). Cache has already gone STALE (max randomised
    //      base_reachable_time_ms = 749 ms, < 1.75 s); USE → DELAY.
    //   3. Sub2 (initial_wait 500 ms) → DUT UDP2 with eth_dst=MAC1
    //      (~t=2.25 s). USE keeps DELAY (no state change on USE during
    //      DELAY, lladdr remains).
    //   4. 2 s sleep covers the DELAY → PROBE transition
    //      (delay_first_probe_time=1) — kernel emits broadcast ARP
    //      Request at ~t=2.75 s (1 s after stim1's USE entered DELAY).
    //      ucast_solicit=0 ensures it's broadcast not unicast probe.
    //
    // Wire-order invariant: stim2's UDP2 (~2.25 s) precedes the
    // PROBE-fired ARP Request (~2.75 s) — that 0.5 s margin is what
    // keeps the SCXML's wait_udp1 → wait_udp2 → wait_arp_request
    // walk well-defined under the per-case sysctl timing.
    static void stimulus(Captured & /*c*/, const ::tc8::TestConfig &cfg, std::string_view iface) {
        ::tc8::stimulus::emitArpLearningBoot(iface, cfg.arp.tester_ip, cfg.arp.dut_real_ip,
                                             ::tc8::stimulus::ArpLearningVariant::Request);

        ::tc8::stimulus::SdBootTiming sub1;
        sub1.initial_wait = std::chrono::milliseconds(1500);
        sub1.retry_interval = std::chrono::milliseconds(0);
        sub1.total_emits = 1;
        ::tc8::stimulus::emitSubscribeEventgroupBoot(iface, ::tc8::stimulus::SubscribeEventgroupTarget{}, sub1);

        ::tc8::stimulus::SdBootTiming sub2;
        sub2.initial_wait = std::chrono::milliseconds(500);
        sub2.retry_interval = std::chrono::milliseconds(0);
        sub2.total_emits = 1;
        ::tc8::stimulus::emitSubscribeEventgroupBoot(iface, ::tc8::stimulus::SubscribeEventgroupTarget{}, sub2);

        std::this_thread::sleep_for(std::chrono::milliseconds(2000));
    }

    static std::string_view verdictFor(State s) {
        switch (s) {
        case State::Pass:
            return "pass";
        case State::Fail_udp1_wrong_eth_dst:
            return "fail:first_udp_eth_dst_not_learned_mac";
        case State::Fail_udp2_wrong_eth_dst:
            return "fail:second_udp_eth_dst_not_learned_mac";
        case State::Fail_no_udp1:
            return "fail:no_first_udp_after_cache_learning";
        case State::Fail_no_udp2:
            return "fail:no_second_udp_in_busy_window";
        case State::Fail_no_arp_request_after_timeout:
            return "fail:no_dut_arp_request_after_cache_timeout";
        default:
            return "running";
        }
    }
};

}  // namespace tc8::sce

TC8_REGISTER_CASE(::tc8::sce::cases::Arp49SM, arp_49)
