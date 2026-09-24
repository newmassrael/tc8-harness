#pragma once

#include <chrono>
#include <cstdint>
#include <string_view>
#include <thread>

#include "tc8/upper_tester_protocol.h"

#include "sce_integration/case_registry.h"
#include "sce_integration/cases/_arp_traits_base.h"
#include "sce_integration/cases/_fault_flavor_arm.h"
#include "sce_integration/test_runner.h"
#include "stimulus/arp_builder.h"
#include "stimulus/boot_timing.h"

#include "arp_49_neg_sm.h"

namespace tc8::sce::cases {

using Arp49NegSM = ::SCE::Generated::arp_49_neg::arp_49_neg;

}  // namespace tc8::sce::cases

namespace tc8::sce {

// UDP-only dispatch, and the first consumer of ArpFaultNegUdpBase's EGRESS seam: this
// negative corrupts what the DUT emits rather than swallowing what it receives.
template <>
struct TestCaseTraits<cases::Arp49NegSM>
    : ArpFaultNegUdpBase<cases::Arp49NegSM, ::tc8::sce::kCapEgressFault> {
    static constexpr std::string_view kCaseId      = "ARP_49_NEG";
    static constexpr std::string_view kDescription =
        "Self-validation of ARP_49's second-UDP guard: kEthFaultUdpEgressDstWrong is armed "
        "BETWEEN the two egress provocations, so the first datagram still rides the learned "
        "MAC and only the second leaves with a destination the DUT never learned";
    // The positive's sequence up to its SECOND UDP, and no further: the third phase
    // (age out the rest, observe the DUT's own Request) belongs to a different final.
    //
    // Arming before the first provocation would corrupt UDP 1 and land the positive's FIRST
    // guard instead — one run reaches one final, which is why the per-final coverage map
    // exists. The settle after the arm is kFlavorArmSettle: the arm is a raw-injected UT
    // frame handled on the DUT's UT thread while the datagram leaves from the tcpip thread.
    static void stimulus(Captured & /*c*/, const ::tc8::TestConfig &cfg, std::string_view iface,
                         ::tc8::sce::IDutControl &dut) {
        ::tc8::stimulus::emitArpLearningBoot(iface, cfg.arp.tester_ip, cfg.dut.ip,
                                             ::tc8::stimulus::ArpLearningVariant::Request);

        ::tc8::stimulus::BootTiming ut1;
        ut1.initial_wait = std::chrono::milliseconds(1500);
        ut1.retry_interval = std::chrono::milliseconds(0);
        ut1.total_emits = 1;
        emitArpEgressProvocation(dut, ut1);

        emitEgressFlavorArmMidStream(cfg, iface, ::tc8::ut::kEthFaultUdpEgressDstWrong);
        std::this_thread::sleep_for(kFlavorArmSettle);

        // The positive's step 8: half the timeout elapses and the entry must SURVIVE, which
        // is what makes the second datagram a cache USE rather than a fresh resolution. Kept
        // so the frame this negative corrupts is the one the positive grades.
        const std::uint16_t timeout_s = cfg.arp_stimulus.ut_cache_conditioning_s;
        if (timeout_s > 0) {
            emitArpCacheConditioning(dut, ::tc8::ut::kArpConditionAgeBySeconds,
                                     static_cast<std::uint16_t>(timeout_s / 2));
        }

        ::tc8::stimulus::BootTiming ut2;
        ut2.initial_wait = std::chrono::milliseconds(500);
        ut2.retry_interval = std::chrono::milliseconds(0);
        ut2.total_emits = 1;
        emitArpEgressProvocation(dut, ut2);
    }
};

}  // namespace tc8::sce

TC8_REGISTER_CASE(::tc8::sce::cases::Arp49NegSM, arp_49_neg)
