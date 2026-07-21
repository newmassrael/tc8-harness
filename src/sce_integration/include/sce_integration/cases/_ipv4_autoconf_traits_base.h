#pragma once

#include <string_view>

#include "tc8/bpf_group.h"
#include "tc8/captured_event.h"
#include "tc8/rfc3927_constants.h"

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
//   - LinklocalRepeatedConflictBase<SM>  4-arg iface-aware
//                                        dispatchArpFrameWithRepeatedConflictEmit
//                                        (per-frame Conflict injection
//                                        cycle), used by ADDRESS_SELECTION_14/_15
//                                        and their _neg variants. The
//                                        post-silence branch (_15's second
//                                        window) is a per-case dispatch
//                                        override.
//
// All three bases pin kBpfGroup=Arp because §4.5 observes the wire-level
// ARP frames emitted by the DUT's autoconfiguration state machine. A base
// PROVIDING the 4-arg dispatch is detected by `has_iface_dispatch_v` through
// inheritance (name lookup resolves `Traits::dispatch` to the inherited
// member), so the repeated-conflict cluster inherits it rather than
// copy-pasting the spec into every trait.
//
// Cases NOT migrated onto these bases:
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

// §4.5.6.2 ADDRESS_SELECTION_14/_15 (+ _neg variants): the per-frame
// Conflict injection cycle. Provides the standard cycle dispatch spec
// (cycle state + Conflicts_complete event, MAX_CONFLICTS cap, no
// post-silence branch). A case that needs the post-silence branch (the
// _15 second-window cases) overrides `dispatch` with the 7-field spec.
// Stimulus is per-case (the timing envelope / buggy flavor differs).
template <typename StateMachine>
struct LinklocalRepeatedConflictBase {
    using SM       = StateMachine;
    using State    = typename StateMachine::PolicyType::State;
    using Event    = typename StateMachine::PolicyType::Event;
    using Captured = typename StateMachine::CapturedType;
    using Expected = typename StateMachine::ExpectedType;

    static constexpr bool             kDeprecated = false;
    static constexpr int              kTopology   = 1;
    static constexpr ::tc8::BpfGroup  kBpfGroup   = ::tc8::BpfGroup::Arp;

    static void dispatch(Captured& c, SM& sm, const ::tc8::CapturedEvent& ev,
                         std::string_view iface) {
        ::tc8::sce::linklocal::RepeatedConflictDispatchSpec<SM> spec{
            iface,
            static_cast<int>(State::Cycle),
            Event::Conflicts_complete,
            ::tc8::sce::linklocal::ConflictArpVariant::Request,
            ::tc8::rfc3927::kMaxConflicts,
        };
        ::tc8::sce::linklocal::dispatchArpFrameWithRepeatedConflictEmit<SM>(
            c, sm, ev, spec);
    }
};

}  // namespace tc8::sce
