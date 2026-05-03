#pragma once

#include "tc8/bpf_group.h"
#include "tc8/captured_event.h"

#include "sce_integration/ipv4_linklocal_common.h"
#include "sce_integration/test_case_traits.h"

// Shared §4.5 IPv4 link-local autoconfiguration trait bases. Two siblings
// cover the two dispatch shapes that recur across the autoconf cluster:
//
//   - LinklocalAutoconfBase<SM>          dispatchArpFrame helper, used by
//                                        33 cases observing ARP Probe /
//                                        Announce / Reply / Request emit
//                                        from the DUT during link-local
//                                        autoconfiguration.
//   - LinklocalProbeSnapshotBase<SM>     dispatchArpFrameWithFirstProbeSnapshot
//                                        helper, used by 3 cases
//                                        (ADDRESS_SELECTION_11..13) that
//                                        need the first probe target_ip
//                                        captured for a subsequent
//                                        Conflict injection cycle.
//
// Both bases pin kBpfGroup=Arp because §4.5 observes the wire-level ARP
// frames emitted by the DUT's autoconfiguration state machine.
//
// Cases NOT migrated onto these bases:
//   - ADDRESS_SELECTION_14/_15: 4-arg iface-aware dispatch with
//     RepeatedConflictDispatchSpec (per-frame Conflict injection cycle);
//     keep verbatim — `has_iface_dispatch_v` SFINAE detects the 4-arg
//     form, base would shadow that detection.
//   - INTRO_01: cross-protocol kBpfGroup=ArpAndDhcpv4 +
//     dispatchArpAndDhcpv4Frame helper; keep verbatim.
//
// Stimulus is intentionally NOT provided here — every §4.5 case has its
// own per-case stimulus (StartLLAutoconf with case-specific timing
// envelope, conflict-injection probes, ...) and `has_stimulus_v` /
// `has_scheduled_stimulus_v` SFINAE in test_case_traits.h would pick up
// an inherited base member, forcing kickStimulus() to fire on every case
// unconditionally.

namespace tc8::sce {

template <typename StateMachine>
struct LinklocalAutoconfBase {
    using SM       = StateMachine;
    using State    = typename StateMachine::PolicyType::State;
    using Event    = typename StateMachine::PolicyType::Event;
    using Captured = typename StateMachine::CapturedType;
    using Expected = typename StateMachine::ExpectedType;

    static constexpr bool             kDeprecated = false;
    static constexpr int              kTopology   = 1;
    static constexpr ::tc8::BpfGroup  kBpfGroup   = ::tc8::BpfGroup::Arp;

    static void dispatch(Captured& c, SM& sm, const ::tc8::CapturedEvent& ev) {
        ::tc8::sce::linklocal::dispatchArpFrame<SM>(c, sm, ev);
    }
};

template <typename StateMachine>
struct LinklocalProbeSnapshotBase : LinklocalAutoconfBase<StateMachine> {
    using Base = LinklocalAutoconfBase<StateMachine>;
    using typename Base::SM;
    using typename Base::Captured;

    static void dispatch(Captured& c, SM& sm, const ::tc8::CapturedEvent& ev) {
        ::tc8::sce::linklocal::dispatchArpFrameWithFirstProbeSnapshot<SM>(c, sm, ev);
    }
};

}  // namespace tc8::sce
