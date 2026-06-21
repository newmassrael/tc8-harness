#pragma once

#include "tc8/bpf_group.h"
#include "tc8/captured_event.h"

#include "sce_integration/dut_capabilities.h"
#include "sce_integration/test_case_traits.h"
#include "sce_integration/udp_pilot_common.h"

// Shared §4.6 UDP trait base. The 30 single-protocol cases under
// DATAGRAMLENGTH / FIELDS / INTRODUCTION_01-02 / INVALID_ADDRESSES /
// MESSAGEFORMAT / PADDING / USER_INTERFACE all share:
//   - identical metadata (kDeprecated=false, kTopology=1, kBpfGroup=Udp)
//   - identical dispatch body — `dispatchUdpFrame<SM>(c, sm, ev)` from
//     udp_pilot_common.h, which already handles variant get_if + fill +
//     raise + step + observed_ts_us tracking.
//
// INTRODUCTION_03 is cross-protocol (UDP stimulus → ICMP observation,
// kBpfGroup=Icmpv4) and intentionally NOT migrated onto this base — it
// keeps a verbatim trait declaring its own metadata and an
// `icmpv4::dispatchAnyIcmpFrame` dispatch body. A second cross-protocol
// case would motivate a `UdpToIcmpBase` sibling; one case alone doesn't.
//
// Stimulus is intentionally NOT provided here — every §4.6 case has its
// own per-case stimulus shape (UT-driven OpTriggerSendUdp / direct
// emitUdpStimulus / ingress probe + UT query / ...) and `has_stimulus_v`
// SFINAE in test_case_traits.h would pick up an inherited base member,
// forcing kickStimulus() to fire on every case unconditionally.

namespace tc8::sce {

template <typename StateMachine>
struct UdpAnyBase {
    using SM       = StateMachine;
    using State    = typename StateMachine::PolicyType::State;
    using Event    = typename StateMachine::PolicyType::Event;
    using Captured = typename StateMachine::CapturedType;
    using Expected = typename StateMachine::ExpectedType;

    static constexpr bool             kDeprecated = false;
    static constexpr int              kTopology   = 1;
    static constexpr ::tc8::BpfGroup  kBpfGroup   = ::tc8::BpfGroup::Udp;

    static void dispatch(Captured& c, SM& sm, const ::tc8::CapturedEvent& ev) {
        ::tc8::sce::udp::dispatchUdpFrame<SM>(c, sm, ev);
    }
};

// Base for the §4.6.5.4 UDP EGRESS field-fault `_NEG` cases (UDP_FIELDS_01/02/06/
// 07/13/14). Same UDP dispatch as UdpAnyBase, plus the one declaration every such
// case shares: it requires the DUT to implement OpSetEgressFlavor (kCapEgressFault).
// The DUT is the SSOT for that (OpQueryCapabilities 0x16), so the Tier-2 gate runs
// these only on the lwIP fixture and capability-skips them (N/A) on the kernel-stack
// reference DUT — the sibling of ArpEgressFaultNegBase on the UDP dispatch.
template <typename StateMachine>
struct UdpEgressFaultNegBase : UdpAnyBase<StateMachine> {
    static constexpr ::tc8::sce::DutCapabilities kRequiredCapabilities =
        ::tc8::sce::kCapEgressFault;
};

}  // namespace tc8::sce
