#pragma once

#include <cstdint>

#include "tc8/bpf_group.h"
#include "tc8/captured_event.h"

#include "sce_integration/icmpv4_pilot_common.h"
#include "sce_integration/test_case_traits.h"

// Shared §4.3 ICMPv4 trait base. The 14 cases under TYPE / ERROR all share
// the same metadata (kDeprecated=false, kTopology=1, kBpfGroup=Icmpv4) and
// hand off dispatch to one of two helpers in `icmpv4_pilot_common.h`:
//
//   - dispatchAnyIcmpFrame(c, sm, ev)             — type-agnostic; only
//                                                   used by ERROR_05 where
//                                                   "any ICMP reply means
//                                                   fail" is the spec
//                                                   invariant.
//   - dispatchIcmpFrame(c, sm, ev, type_byte)     — narrows the captured
//                                                   variant to a specific
//                                                   ICMP type (Echo Reply
//                                                   = 0, Time Exceeded =
//                                                   11, Parameter Problem
//                                                   = 12, Destination
//                                                   Unreachable = 3,
//                                                   Information Reply =
//                                                   16, ...).
//
// Sibling-via-chain bases collapse the per-case alias + metadata + dispatch
// wrapper boilerplate while keeping the type-narrowing axis explicit at the
// inheritance line:
//
//   - Icmpv4AnyBase<SM>                        — type-agnostic dispatch.
//   - Icmpv4TypedBase<SM, ExpectedReplyType>   — inherits Icmpv4AnyBase and
//                                                shadows dispatch with the
//                                                type-narrowing helper.
//
// Stimulus is intentionally NOT provided here — `has_stimulus_v` SFINAE in
// test_case_traits.h would otherwise pick up an inherited base member,
// forcing kickStimulus() to fire on every case. Every §4.3 case has its
// own per-case stimulus shape (Echo Request / Timestamp Request / fragmented
// payload / corrupt checksum / unknown type / ...), and the case header
// declares it directly.

namespace tc8::sce {

template <typename StateMachine>
struct Icmpv4AnyBase {
    using SM       = StateMachine;
    using State    = typename StateMachine::PolicyType::State;
    using Event    = typename StateMachine::PolicyType::Event;
    using Captured = typename StateMachine::CapturedType;
    using Expected = typename StateMachine::ExpectedType;

    static constexpr bool             kDeprecated = false;
    static constexpr int              kTopology   = 1;
    static constexpr ::tc8::BpfGroup  kBpfGroup   = ::tc8::BpfGroup::Icmpv4;

    static void dispatch(Captured& c, SM& sm, const ::tc8::CapturedEvent& ev) {
        ::tc8::sce::icmpv4::dispatchAnyIcmpFrame(c, sm, ev);
    }
};

template <typename StateMachine, std::uint8_t ExpectedReplyType>
struct Icmpv4TypedBase : Icmpv4AnyBase<StateMachine> {
    using Base = Icmpv4AnyBase<StateMachine>;
    using typename Base::SM;
    using typename Base::Captured;

    static void dispatch(Captured& c, SM& sm, const ::tc8::CapturedEvent& ev) {
        ::tc8::sce::icmpv4::dispatchIcmpFrame(c, sm, ev, ExpectedReplyType);
    }
};

}  // namespace tc8::sce
