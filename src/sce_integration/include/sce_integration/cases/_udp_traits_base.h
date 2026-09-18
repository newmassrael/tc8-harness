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

// Base for every UDP case whose procedure needs the DUT to ORIGINATE a datagram
// (the `emitTriggerSendUdp` step). Same UDP dispatch as UdpAnyBase, plus the one
// declaration they all share: the harness cannot make a DUT send anything from
// the wire, so the ask goes over the Tier-2 seam and the case needs the selected
// backend to provide IUdpControl.
//
// Declaring it here rather than in each case is what keeps the requirement from
// being forgotten by the next case that needs it — and without the declaration
// the gate cannot fire at all, so the case would sit out its listen window and
// report a non-conclusion that reads like a DUT fault rather than "not
// measurable on this backend".
template <typename StateMachine>
struct UdpDutOriginatedBase : UdpAnyBase<StateMachine> {
    static constexpr ::tc8::sce::DutCapabilities kRequiredCapabilities =
        ::tc8::sce::kCapUdpControl;
};

// Base for every UDP case that asks the DUT what it RECEIVED — the probe goes out
// on the wire, but the answer comes from the DUT over the seam, so the case is
// only measurable on a backend providing IUdpReceiveControl. Declared here rather
// than per case for the same reason as UdpDutOriginatedBase: so the next case
// that asks the question cannot forget to say it needs an answerer.
template <typename StateMachine>
struct UdpReceiveDrivenBase : UdpAnyBase<StateMachine> {
    static constexpr ::tc8::sce::DutCapabilities kRequiredCapabilities =
        ::tc8::sce::kCapUdpReceiveControl;

    // The answer comes back as an Upper Tester Confirmation on the wire, and the
    // SCXML grades that frame (`captured.has_ut_response and ut_opcode == 0x81`).
    // So for this family the DUT-control channel is the evidence, and the capture
    // path must not withhold it — the one place where that is true by
    // construction rather than per case. Declared here and not derived from
    // `kRequiredCapabilities`: the two sets are ALMOST the same and not quite,
    // which is exactly the kind of near-coincidence that silently breaks the odd
    // case out (IPv4_ADDRESSING_01/02 grade the same Confirmation from verbatim
    // traits and would have been missed).
    static constexpr ::tc8::sce::ControlPlaneRole kControlPlaneRole =
        ::tc8::sce::ControlPlaneRole::kEvidence;
};

// Base for the §4.6.5.4 UDP EGRESS field-fault `_NEG` cases (UDP_FIELDS_01/02/06/
// 07/13/14). Same UDP dispatch as UdpAnyBase, plus the one declaration every such
// case shares: it requires the DUT to implement OpSetEgressFlavor (kCapEgressFault).
// The DUT is the SSOT for that (OpQueryCapabilities 0x16), so the Tier-2 gate runs
// these only on the lwIP fixture and capability-skips them (N/A) on the kernel-stack
// reference DUT — the sibling of ArpEgressFaultNegBase on the UDP dispatch.
// Every case on this base also drives the faulty datagram out of the DUT itself,
// so it carries the DUT-originated requirement alongside the fault one — both
// bits, because the gate needs either absence to skip honestly.
template <typename StateMachine>
struct UdpEgressFaultNegBase : UdpAnyBase<StateMachine> {
    static constexpr ::tc8::sce::DutCapabilities kRequiredCapabilities =
        ::tc8::sce::kCapEgressFault | ::tc8::sce::kCapUdpControl;
};

// Base for the §4.6.5.4 UDP INGRESS acceptance-fault `_NEG` cases (UDP_FIELDS_09/10/
// 15). Same UDP dispatch as UdpAnyBase, plus the one declaration every such case
// shares: it requires the DUT to implement OpSetIngressFlavor (kCapIngressFault).
// The DUT is the SSOT for that (OpQueryCapabilities 0x16), so the Tier-2 gate runs
// these only on the lwIP fixture and capability-skips them (N/A) on the kernel-stack
// reference DUT — the sibling of ArpIngressFaultNegBase on the UDP dispatch. The
// armed flavor (kUdpFaultAcceptBadChecksum) makes the fixture zero the inbound UDP
// checksum so lwIP accepts a datagram its checksum check must drop; a conformant DUT
// still drops it, landing the template's fault_injection_inert fail branch.
template <typename StateMachine>
struct UdpIngressFaultNegBase : UdpAnyBase<StateMachine> {
    // Every case here also asks the DUT what it received, so it carries both —
    // the gate must skip on either absence.
    static constexpr ::tc8::sce::DutCapabilities kRequiredCapabilities =
        ::tc8::sce::kCapIngressFault | ::tc8::sce::kCapUdpReceiveControl;
    // And it grades the Confirmation that answers it, so the control channel is
    // this family's evidence — as for UdpReceiveDrivenBase. Stated here rather
    // than left to the gate: these cases capability-skip on the reference DUT, so
    // a missing declaration would not show up as a regression on a run that does
    // not reach the fault fixture.
    static constexpr ::tc8::sce::ControlPlaneRole kControlPlaneRole =
        ::tc8::sce::ControlPlaneRole::kEvidence;
};

// Base for the §4.6.5.6 UDP APP-LAYER reception-fault `_NEG` cases (INTRODUCTION_02).
// Same UDP dispatch as UdpAnyBase, plus the one declaration it shares: it requires the
// DUT to implement OpSetAppFlavor (kCapAppFault). The discard under test is an
// application decision in the shared data listener (not a netif-level wire fault), so a
// conformant DUT still drops the multicast and the case lands the template's
// fault_injection_inert fail branch; the lwIP fixture registers the opcode and runs it,
// the kernel-backed reference DUT capability-skips (N/A). Sibling of the IPv4
// ipv4_addressing_02_neg app-fault case on the UDP dispatch.
template <typename StateMachine>
struct UdpAppFaultNegBase : UdpAnyBase<StateMachine> {
    // As UdpIngressFaultNegBase: the receipt question is part of every case here.
    static constexpr ::tc8::sce::DutCapabilities kRequiredCapabilities =
        ::tc8::sce::kCapAppFault | ::tc8::sce::kCapUdpReceiveControl;
    // As UdpIngressFaultNegBase, and skipped on the reference DUT for the same
    // reason, so the declaration cannot wait for a run to demand it.
    static constexpr ::tc8::sce::ControlPlaneRole kControlPlaneRole =
        ::tc8::sce::ControlPlaneRole::kEvidence;
};

}  // namespace tc8::sce
