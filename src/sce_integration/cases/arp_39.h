#pragma once

#include <string_view>
#include <chrono>

#include "sce_integration/case_registry.h"
#include "sce_integration/cases/_arp_traits_base.h"
#include "sce_integration/test_runner.h"
#include "stimulus/arp_builder.h"
#include "stimulus/boot_timing.h"

#include "arp_39_sm.h"

namespace tc8::sce::cases {

using Arp39SM = ::SCE::Generated::arp_39::arp_39;

}  // namespace tc8::sce::cases

namespace tc8::sce {

template <>
struct TestCaseTraits<cases::Arp39SM>
    : ArpAndUdpBase<cases::Arp39SM> {
    static constexpr std::string_view kCaseId = "ARP_39";
    static constexpr std::string_view kSpecSection = "4.2.4.2";
    static constexpr std::string_view kDescription =
        "ARP learning via received Request — DUT must populate cache from "
        "tester-injected Request and use it for subsequent UDP egress";
    // Two-phase split-stimulus matching spec steps 4 → 5 → 9:
    //   1. UT 0x02 OpTriggerSendUdp (the spec's "Configure DUT to send a
    //      UDP Message" step, literally) → DUT queues the UT response +
    //      triggered datagram toward tester_ip, hits cold cache,
    //      broadcasts ARP Request (spec step 4 — SCXML wait_dut_request
    //      observes).
    //   2. Inject ARP Request with sender_hw = MAC-ADDR2 (spec step 5).
    //      Linux populates neigh table via RFC 826 §2.3 (sender_ip is
    //      tester_ip, target_ip is DUT_IP so DUT is the target). The
    //      kernel queue-pending UDP from step 1 immediately drains via
    //      `neigh_resolve_output_skb_queue` once the entry transitions
    //      from INCOMPLETE to REACHABLE — Eth-dst = MAC2 (spec step 9).
    //
    // Tester-side `arp_ignore=8` (set by smoke-test.sh per case) prevents
    // the kernel from auto-replying to step-1's broadcast — without it,
    // the kernel's Reply lands first and Linux's `neigh_update` rules
    // refuse to override the resulting REACHABLE entry from our later
    // injection. Confirmed via pcap analysis on first attempt: pre-fix
    // the DUT's UDP carried the kernel's veth MAC instead of MAC2.
    //
    // No second UT request needed — the queued frames from step 1 drain
    // exactly once when the ARP entry resolves.
    static void stimulus(Captured & /*c*/, const ::tc8::TestConfig &cfg, std::string_view iface) {
        // Single UT request with full bootstrap initial_wait (tc8-dut
        // starts ~0.5 s after harness; 1500 ms gives ample margin).
        ::tc8::stimulus::BootTiming ut_timing;
        ut_timing.initial_wait = std::chrono::milliseconds(1500);
        ut_timing.retry_interval = std::chrono::milliseconds(0);
        ut_timing.total_emits = 1;
        emitArpEgressProvocation(cfg, iface, ut_timing);

        // emitArpFromTester's default 200 ms settle gives the DUT's
        // own broadcast Request time to reach pcap before our injection.
        ::tc8::stimulus::ArpFrameSpec spec;
        spec.opcode = 0x0001;  // Request — spec ARP_39 inject form
        spec.sender_hw = ::tc8::stimulus::kTesterInjectedMac2;
        spec.eth_src = ::tc8::stimulus::kTesterInjectedMac2;
        spec.sender_ip_be = cfg.arp.tester_ip;
        spec.target_ip_be = cfg.dut.ip;
        ::tc8::stimulus::emitArpFromTester(iface, spec);
    }
};

}  // namespace tc8::sce

TC8_REGISTER_CASE(::tc8::sce::cases::Arp39SM, arp_39)
