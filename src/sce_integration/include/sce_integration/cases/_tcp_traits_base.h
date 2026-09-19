#pragma once

#include "tc8/bpf_group.h"
#include "tc8/captured_event.h"

#include "sce_integration/dut_capabilities.h"
#include "sce_integration/tcp_pilot_common.h"
#include "sce_integration/test_case_traits.h"

// Shared §4.8 TCP trait base. Single base covers 112 of 113 cases —
// the cluster has uniform metadata (kDeprecated=false, kTopology=1,
// kBpfGroup=Tcp) and uniform dispatch (`tcp::dispatchTcpFrame<SM>` does
// the variant get_if + fill + raise + step + frame_delta_us tracking).
//
// The 113th case — TCP_RETRANSMISSION_TO_03 — stays verbatim because
// its dispatch is a deliberate no-op: verdict is computed from
// kernel-side TCP_INFO snapshots inside stimulus(), so frame ingress
// is not consulted (see `reference_op_query_tcp_info.md`).
//
// Stimulus is intentionally NOT provided here — every §4.8 case has its
// own per-case stimulus shape (active-OPEN / passive-listen handshake
// drivers, raw segment injection, scheduled retransmission, ...) and
// `has_stimulus_v` SFINAE in test_case_traits.h would pick up an
// inherited base member, forcing kickStimulus() to fire on every case.

namespace tc8::sce {

template <typename StateMachine>
struct TcpAnyBase {
    using SM       = StateMachine;
    using State    = typename StateMachine::PolicyType::State;
    using Event    = typename StateMachine::PolicyType::Event;
    using Captured = typename StateMachine::CapturedType;
    using Expected = typename StateMachine::ExpectedType;

    static constexpr bool             kDeprecated = false;
    static constexpr int              kTopology   = 1;
    static constexpr ::tc8::BpfGroup  kBpfGroup   = ::tc8::BpfGroup::Tcp;

    static void dispatch(Captured& c, SM& sm, const ::tc8::CapturedEvent& ev) {
        ::tc8::sce::tcp::dispatchTcpFrame<SM>(c, sm, ev);
    }
};

// Base for the §4.8 cases that DRIVE the DUT's TCP data plane over the Tier-2
// seam — connectTcp / listenTcp / sendTcp / receiveTcp / closeTcp, reached
// through `seamTcpControl` or one of the `_tcp_seam*.h` helpers. Same dispatch
// as TcpAnyBase, plus the declaration that lets the capability gate decline a
// backend with no ITcpControl.
//
// The declaration is not hygiene here, it is the CONTRACT `seamTcpControl`
// names: it asserts the pointer is non-null "because the gate already skipped
// this case", so a case that reaches the seam without declaring is relying on
// an invariant it never established. Under NDEBUG that assert compiles out and
// the deref is undefined rather than an honest skip.
//
// Separate from TcpAnyBase and not folded into it because only 81 of that
// base's 109 cases reach the seam; the other 28 drive the DUT entirely from the
// tester side (`emitTcpFrame`) and are measurable on any backend. Declaring on
// the shared base would capability-skip those 28 for a sub-interface they never
// touch — the same axis split ArpDutProvokedBase exists for.
template <typename StateMachine>
struct TcpDutDrivenBase : TcpAnyBase<StateMachine> {
    static constexpr ::tc8::sce::DutCapabilities kRequiredCapabilities =
        ::tc8::sce::kCapTcpControl;
};

// Base for the §4.8 TCP EGRESS field-fault `_NEG` cases. Same TCP dispatch as
// TcpAnyBase, plus the one declaration every such case shares: it requires the DUT to
// implement OpSetEgressFlavor (kCapEgressFault). The Tier-2 gate runs these only on
// the lwIP fixture and capability-skips them (N/A) on the kernel-stack reference DUT —
// the TCP sibling of UdpEgressFaultNegBase. The armed flavor corrupts one field of a
// specific DUT-emitted segment (segment-selective; see lwip_egress_fault.cpp).
template <typename StateMachine>
struct TcpEgressFaultNegBase : TcpAnyBase<StateMachine> {
    static constexpr ::tc8::sce::DutCapabilities kRequiredCapabilities =
        ::tc8::sce::kCapEgressFault;
};

// The half of that family whose procedure also DRIVES the DUT over the seam
// (11 of 26 — the rest arm the flavor and then inject every segment from the
// tester). Both bits are restated because this declaration SHADOWS the one
// above rather than extending it; dropping either silently removes a
// requirement, which is how DHCPv4 CM_05/06 lost their DHCP bit.
template <typename StateMachine>
struct TcpEgressFaultNegDrivenBase : TcpAnyBase<StateMachine> {
    static constexpr ::tc8::sce::DutCapabilities kRequiredCapabilities =
        ::tc8::sce::kCapEgressFault | ::tc8::sce::kCapTcpControl;
};

// Base for the §4.8 TCP behavioral INGRESS `_NEG` cases (ACKNOWLEDGEMENT_04). The positive
// proves the DUT stays silent for an inbound segment RFC 793 §3.9 says it must accept; the
// `_NEG` arms kTcpSynthRst so the lwIP netif INPUT hook synthesizes the prohibited RST, and
// the case passes only when it is observed. Same TCP dispatch as TcpAnyBase, plus the
// kCapIngressFault declaration (OpSetIngressFlavor), so the Tier-2 gate runs these only on
// the lwIP fixture. The ingress sibling of TcpEgressFaultNegBase: there the DUT emits a
// segment whose field is corrupted; here the DUT emits nothing, so the hook synthesizes the
// whole frame (the behavioral seam the egress field-fault cannot reach).
template <typename StateMachine>
struct TcpIngressFaultNegBase : TcpAnyBase<StateMachine> {
    static constexpr ::tc8::sce::DutCapabilities kRequiredCapabilities =
        ::tc8::sce::kCapIngressFault;
};

// As TcpEgressFaultNegDrivenBase, for the ingress family: the 18 of 39 whose
// procedure drives the DUT over the seam as well as arming the fault.
template <typename StateMachine>
struct TcpIngressFaultNegDrivenBase : TcpAnyBase<StateMachine> {
    static constexpr ::tc8::sce::DutCapabilities kRequiredCapabilities =
        ::tc8::sce::kCapIngressFault | ::tc8::sce::kCapTcpControl;
};

}  // namespace tc8::sce
