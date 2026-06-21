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

}  // namespace tc8::sce
