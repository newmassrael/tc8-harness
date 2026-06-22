#pragma once

#include <string_view>

#include "tc8/bpf_group.h"
#include "tc8/captured_event.h"
#include "tc8/upper_tester_protocol.h"

#include "sce_integration/case_registry.h"
#include "sce_integration/cases/_fault_flavor_arm.h"
#include "sce_integration/cases/ipv4_addressing_02.h"  // SSOT for kDirectedBroadcastBe
#include "sce_integration/dut_capabilities.h"
#include "sce_integration/test_case_traits.h"
#include "sce_integration/test_runner.h"
#include "sce_integration/udp_captured.h"
#include "sce_integration/udp_pilot_common.h"

#include "ipv4_addressing_02_neg_sm.h"

namespace tc8::sce::cases {

using Ipv4Addressing02NegSM =
    ::SCE::Generated::ipv4_addressing_02_neg::ipv4_addressing_02_neg;

}  // namespace tc8::sce::cases

namespace tc8::sce {

// Self-validation of IPv4_ADDRESSING_02: the §4.4.4.5 directed-broadcast discard is an
// application decision (RFC 1122) — lwIP delivers the directed broadcast to the
// INADDR_ANY data-listener socket and the listener drops it on the recovered
// destination address. The kAppFaultAcceptDirectedBroadcast app fault makes that
// listener skip the discard, so a buggy DUT counts the datagram the positive proves
// dropped. A verbatim trait (not the UdpAnyBase dispatch base) mirroring the positive
// ipv4_addressing_02: same metadata, same directed-broadcast probe, plus the fault arm
// and the kCapAppFault requirement. lwIP-only — the kernel-backed tc8-dut omits
// OpSetAppFlavor (kCapAppFault absent), so the Tier-2 gate capability-skips it (N/A).
template <>
struct TestCaseTraits<cases::Ipv4Addressing02NegSM> {
    using SM    = cases::Ipv4Addressing02NegSM;
    using State = SM::PolicyType::State;
    using Event = SM::PolicyType::Event;

    static constexpr std::string_view kCaseId       = "IPv4_ADDRESSING_02_NEG";
    static constexpr std::string_view kSpecSection  = "4.4.4.5";
    static constexpr std::string_view kDescription  =
        "Self-validation of IPv4_ADDRESSING_02: the lwIP kAppFaultAcceptDirectedBroadcast "
        "app fault makes the data listener count a directed-broadcast datagram; a "
        "conformant DUT discards it at the application layer";
    static constexpr bool             kDeprecated   = false;
    static constexpr int              kTopology     = 1;
    static constexpr ::tc8::BpfGroup  kBpfGroup     = ::tc8::BpfGroup::Udp;

    static constexpr ::tc8::sce::DutCapabilities kRequiredCapabilities =
        ::tc8::sce::kCapAppFault;

    using Captured = typename SM::CapturedType;
    using Expected = typename SM::ExpectedType;

    // Arm the app-layer acceptance fault, then drive the same directed-broadcast probe
    // + UT GetReceivedUdp query the positive uses (the directed-broadcast destination is
    // the only wire-level shape; the SCXML's {$expected_received}=1 flip and the armed
    // flavor are what make it a negative). With the flavor armed the data listener skips
    // its discard so ut_received == 1.
    static void stimulus(Captured& /*c*/,
                         const ::tc8::TestConfig& cfg,
                         std::string_view iface) {
        emitAppFlavorArm(cfg, iface, ::tc8::ut::kAppFaultAcceptDirectedBroadcast);
        ::tc8::sce::udp::emitAddressingProbeAndQuery(
            cfg, iface, cases::kDirectedBroadcastBe, cfg.dut.mac);
    }

    static void dispatch(Captured& c, SM& sm, const ::tc8::CapturedEvent& ev) {
        ::tc8::sce::udp::dispatchUdpFrame<SM>(c, sm, ev);
    }
};

}  // namespace tc8::sce

TC8_REGISTER_CASE(::tc8::sce::cases::Ipv4Addressing02NegSM, ipv4_addressing_02_neg)
