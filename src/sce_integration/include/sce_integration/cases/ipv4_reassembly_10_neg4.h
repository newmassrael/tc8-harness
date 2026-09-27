#pragma once

#include <chrono>
#include <string_view>
#include <thread>

#include "tc8/upper_tester_protocol.h"

#include "sce_integration/case_registry.h"
#include "sce_integration/cases/_fault_flavor_arm.h"
#include "sce_integration/cases/_ipv4_traits_base.h"
#include "sce_integration/ipv4_reassembly_common.h"
#include "sce_integration/test_runner.h"

#include "ipv4_reassembly_10_neg4_sm.h"

namespace tc8::sce::cases {

using Ipv4Reassembly10Neg4SM = ::SCE::Generated::ipv4_reassembly_10_neg4::ipv4_reassembly_10_neg4;

}  // namespace tc8::sce::cases

namespace tc8::sce {

// Self-validation of §4.4.4.7 IPv4_REASSEMBLY_10's phase B guard
// (dut_replied_phase_b_after_timer_expired). The other three negatives of this case all
// grade phase A; this one is the only reason the mid-stream arm exists here.
// lwIP-only (kCapIngressFault).
template <>
struct TestCaseTraits<cases::Ipv4Reassembly10Neg4SM>
    : Ipv4ReassemblyFaultNegBase<cases::Ipv4Reassembly10Neg4SM, ::tc8::sce::kCapIngressFault> {
    static constexpr std::string_view kCaseId      = "IPv4_REASSEMBLY_10_NEG4";
    static constexpr std::string_view kDescription =
        "Self-validation of IPv4_REASSEMBLY_10 phase B: the lwIP kIpv4FaultHoldFirstFragment "
        "ingress flavor defers phase B's head and replays it ahead of its tail, so the pair "
        "completes despite the wire gap; a conformant DUT stays silent once the bucket expired";

    // Both of the positive's phases, with the arm between them. Phase A must run with the
    // flavour DISARMED: it would defer phase A's head the same way and the run would
    // settle on a phase-A final instead of reaching the guard this negative is for.
    static void stimulus(Captured& /*c*/,
                         const ::tc8::TestConfig& cfg,
                         ::tc8::sce::StimulusContext& ctx) {
        ::tc8::sce::ipv4::reassembly::emitReassembly10PhaseA(cfg, ctx.iface);
        emitIngressFlavorArmMidStream(cfg, ctx.iface, ::tc8::ut::kIpv4FaultHoldFirstFragment);
        // The arm is a raw-injected UT frame handled on the DUT's UT thread while phase B's
        // head arrives on the netif-input thread; the two need a gap, not an ordering
        // guarantee. Same settle the ARP mid-stream negatives use.
        std::this_thread::sleep_for(kFlavorArmSettle);
        ::tc8::sce::ipv4::reassembly::emitReassembly10PhaseB(cfg, ctx.iface);
    }
};

}  // namespace tc8::sce

TC8_REGISTER_CASE(::tc8::sce::cases::Ipv4Reassembly10Neg4SM, ipv4_reassembly_10_neg4)
