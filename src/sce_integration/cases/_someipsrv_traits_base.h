#pragma once

#include <string_view>
#include <variant>

#include "tc8/bpf_group.h"
#include "tc8/captured_event.h"

#include "sce_integration/dut_capabilities.h"
#include "sce_integration/someip_captured.h"
#include "sce_integration/test_case_traits.h"

// Shared §5.1.5 SOMEIPSRV trait base. The 48 cases under FORMAT (27)
// + OPTIONS (8) + SD_MESSAGE (13) all share the same dispatch shape
// (variant-check → optional service_id filter → fillSomeIpCapturedFromFrame
// → raiseExternal → step) and identical metadata
// (kDeprecated=false, kTopology=1, kBpfGroup=SomeIp). Two sibling-via-chain
// bases collapse the boilerplate while keeping the SD-vs-any axis explicit
// at the inheritance line:
//
//   - SomeIpAnyBase<SM>      observes any SOME/IP frame (FORMAT_01..06,
//                            OPTIONS_01..07/15). The SD parser inside
//                            fillSomeIpCapturedFromFrame is itself gated
//                            on service_id == 0xFFFF, so non-SD frames
//                            are filled with empty SD slots that won't
//                            match an SCXML cond on entries[0].
//   - SomeIpSdOnlyBase<SM>   inherits SomeIpAnyBase and shadows dispatch
//                            with an extra service_id == 0xFFFF guard
//                            so non-SD frames don't waste a tick raising
//                            Someip_notification (FORMAT_07..28 minus 22,
//                            SD_MESSAGE_03..19 minus the deferred subset).
//
// Stimulus is intentionally NOT provided here: the `has_stimulus_v` SFINAE
// detector in test_case_traits.h resolves `Traits::stimulus(...)` via
// ordinary name lookup, so an inherited base member would make every case
// test true and force kickStimulus() to fire on every case. Cases that
// genuinely need stimulus (FORMAT_12/13 + FORMAT_19..28-22 +
// SD_MESSAGE_11/14..19) declare it in their own specialization.

namespace tc8::sce {

template <typename StateMachine>
struct SomeIpAnyBase {
    using SM       = StateMachine;
    using State    = typename SM::PolicyType::State;
    using Event    = typename SM::PolicyType::Event;
    using Captured = typename SM::CapturedType;
    using Expected = typename SM::ExpectedType;

    static constexpr bool             kDeprecated = false;
    static constexpr int              kTopology   = 1;
    static constexpr ::tc8::BpfGroup  kBpfGroup   = ::tc8::BpfGroup::SomeIp;

    static void dispatch(Captured& c, SM& sm, const ::tc8::CapturedEvent& ev) {
        const auto* f = std::get_if<::tc8::SomeIpFrame>(&ev);
        if (f == nullptr) return;
        ::tc8::fillSomeIpCapturedFromFrame(c, *f);
        const auto state_before = sm.getCurrentState();
        sm.raiseExternal(Event::Someip_notification);
        sm.step();
        // §5.1.5.4 SD_BEHAVIOR_01/_02 read inter-frame deltas via
        // `SomeIpCaptured::frame_delta_us()`. Snapshot prev only when
        // the SCXML transitioned on this frame so non-fired frames
        // (filter mismatches, cyclic offers between two phase
        // boundaries) never pollute the delta. Mirrors the
        // tcp_pilot_common / udp_pilot_common dispatch pattern.
        if (sm.getCurrentState() != state_before) {
            c.prev_observed_ts_us = c.observed_ts_us;
            c.prev_sd_session_id = c.session_id;
        }
    }
};

// §5.1.6 SOMEIP_ETS field get/set `_NEG` base: inherits the any-frame observe dispatch and
// gates the case on kCapEtsFault, so it runs only on a DUT that registers UT 0x1B
// OpSetEtsFlavor (the reference tc8-dut, whose harness-owned EtsImpl carries the field-getter
// fault) and capability-skips on the lwIP fixture (no SOME/IP service).
template <typename StateMachine>
struct SomeIpEtsFaultNegBase : SomeIpAnyBase<StateMachine> {
    static constexpr ::tc8::sce::DutCapabilities kRequiredCapabilities =
        ::tc8::sce::kCapEtsFault;
};

template <typename StateMachine>
struct SomeIpSdOnlyBase : SomeIpAnyBase<StateMachine> {
    using Base = SomeIpAnyBase<StateMachine>;
    using typename Base::SM;
    using typename Base::Event;
    using typename Base::Captured;

    static void dispatch(Captured& c, SM& sm, const ::tc8::CapturedEvent& ev) {
        const auto* f = std::get_if<::tc8::SomeIpFrame>(&ev);
        if (f == nullptr || f->service_id != 0xFFFF) return;
        ::tc8::fillSomeIpCapturedFromFrame(c, *f);
        const auto state_before = sm.getCurrentState();
        sm.raiseExternal(Event::Someip_notification);
        sm.step();
        if (sm.getCurrentState() != state_before) {
            c.prev_observed_ts_us = c.observed_ts_us;
            c.prev_sd_session_id = c.session_id;
        }
    }
};

}  // namespace tc8::sce
