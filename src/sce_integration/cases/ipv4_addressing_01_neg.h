#pragma once

#include <string_view>

#include "tc8/bpf_group.h"
#include "tc8/captured_event.h"
#include "tc8/upper_tester_protocol.h"

#include "sce_integration/case_registry.h"
#include "sce_integration/cases/_fault_flavor_arm.h"
#include "sce_integration/cases/ipv4_addressing_01.h"  // SSOT for kLimitedBroadcastBe
#include "sce_integration/dut_capabilities.h"
#include "sce_integration/test_case_traits.h"
#include "sce_integration/test_runner.h"
#include "sce_integration/udp_captured.h"
#include "sce_integration/udp_pilot_common.h"

#include "ipv4_addressing_01_neg_sm.h"

namespace tc8::sce::cases {

using Ipv4Addressing01NegSM =
    ::SCE::Generated::ipv4_addressing_01_neg::ipv4_addressing_01_neg;

}  // namespace tc8::sce::cases

namespace tc8::sce {

// Self-validation of §4.4.4.5 IPv4_ADDRESSING_01: the lwIP kUdpFaultRejectValid ingress flavor
// makes the input hook swallow the inbound limited-broadcast datagram (never forwards
// it to lwIP), so the receive-counting app never sees one the DUT must receive; a
// conformant DUT still receives it (ut_received == 1, the fault-inert branch). A
// verbatim trait (mirroring the positive ipv4_addressing_01) that requires
// kCapIngressFault. lwIP-only — the kernel-backed tc8-dut omits OpSetIngressFlavor, so
// the Tier-2 gate capability-skips it (N/A).
template <>
struct TestCaseTraits<cases::Ipv4Addressing01NegSM> {
    using SM    = cases::Ipv4Addressing01NegSM;
    using State = SM::PolicyType::State;
    using Event = SM::PolicyType::Event;

    static constexpr std::string_view kCaseId       = "IPv4_ADDRESSING_01_NEG";
    static constexpr std::string_view kSpecSection  = "4.4.4.5";
    static constexpr std::string_view kDescription  =
        "Self-validation of IPv4_ADDRESSING_01: the lwIP kUdpFaultRejectValid ingress "
        "flavor makes the DUT drop a limited-broadcast datagram; a conformant DUT receives it";
    static constexpr bool             kDeprecated   = false;
    static constexpr int              kTopology     = 1;
    static constexpr ::tc8::BpfGroup  kBpfGroup     = ::tc8::BpfGroup::Udp;

    static constexpr ::tc8::sce::DutCapabilities kRequiredCapabilities =
        ::tc8::sce::kCapIngressFault;

    using Captured = typename SM::CapturedType;
    using Expected = typename SM::ExpectedType;

    static void stimulus(Captured& /*c*/,
                         const ::tc8::TestConfig& cfg,
                         std::string_view iface) {
        emitIngressFlavorArm(cfg, iface, ::tc8::ut::kUdpFaultRejectValid);
        ::tc8::sce::udp::emitAddressingProbeAndQuery(
            cfg, iface, cases::kLimitedBroadcastBe, cfg.dut.mac);
    }

    static void dispatch(Captured& c, SM& sm, const ::tc8::CapturedEvent& ev) {
        ::tc8::sce::udp::dispatchUdpFrame<SM>(c, sm, ev);
    }
};

}  // namespace tc8::sce

TC8_REGISTER_CASE(::tc8::sce::cases::Ipv4Addressing01NegSM, ipv4_addressing_01_neg)
