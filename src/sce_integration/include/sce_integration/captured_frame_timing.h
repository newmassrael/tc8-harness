#pragma once

#include <cstdint>

namespace tc8 {

// Shared inter-frame timing surface for every SCE Named Context that
// observes a wire frame's pcap arrival timestamp. Owns the two epoch
// timestamps and the single delta accessor — defined ONCE so the
// first-transition guard semantics cannot drift across protocols.
//
// `observed_ts_us` is the wall-clock arrival timestamp (microseconds
// since the Unix epoch) of the most-recently-dispatched frame, mirrored
// from the corresponding `*Frame::observed_ts_us` on every fill
// regardless of whether the SCXML guard fires. `prev_observed_ts_us` is
// the timestamp of the frame that fired the most recent SCXML
// transition: every protocol's dispatch helper advances it — together
// with the `fired_frame_delta_us` latch — through the one `snapshotFired()`
// SSOT below, called ONLY when `getCurrentState()` advances, so non-fired
// frames between two state advances never pollute the gap.
//
// The two are a MATCHED PAIR and `snapshotFired()` is the only supported
// way to move them: the latch must capture `frame_delta_us()` before the
// `prev` assignment invalidates it. Assigning `prev_observed_ts_us`
// directly at a dispatch site is what made the trace's `frame_delta_us`
// structurally 0 for every frame-driven step.
//
// `frame_delta_us()` returns the microsecond gap between the current
// frame and the most-recently-fired-transition frame. The
// `prev_observed_ts_us == 0` guard returns 0 when no prior transition
// has fired, so a first-transition guard reads an unbiased 0 rather than
// `observed_ts_us` itself (an enormous epoch-relative number). Cases
// that gate on the delta — TCP RETRANSMISSION_TO_04/_05/_06, DHCPv4
// REACQUISITION_05/_06, SOME/IP-SD SD_BEHAVIOR_01/_02 — therefore guard
// the FIRST transition on structural conjuncts alone and read the delta
// only from the second fired transition onward. This base is shared
// infrastructure, so the authoritative per-section spec citations stay
// in each protocol's `*_captured.h` header rather than here.
//
// Inherited (not composed as a nested member) so SCXML conditions keep
// the single-dot `cpp:captured.frame_delta_us()` form that SCE's
// expression rewriter requires — it rewrites `captured.X` into
// `this->captured_->X` but not `captured.X.Y` (see
// reference_sce_captured_arg.md). Through a derived pointer, inherited
// member and method access stays single-dot, so the rewrite applies
// uniformly.
//
// The type has only data + non-virtual methods, so a Captured struct
// that derives from it remains an aggregate under C++17 (a public base
// with no user-declared constructors is permitted), keeping the existing
// `TcpCaptured c{};` value-initialisation and POD copy semantics intact.
// It shares no common ancestor with `CapturedPayloadSnapshot`, so the
// four L4 contexts that derive from both bases carry two independent
// data-only subobjects with no diamond.
struct CapturedFrameTiming {
    std::int64_t observed_ts_us = 0;
    std::int64_t prev_observed_ts_us = 0;

    // The value `frame_delta_us()` returned at the instant the most recent
    // SCXML transition FIRED — latched by `snapshotFired()` before
    // `prev_observed_ts_us` advances past it. This is a RECORD of a past
    // evaluation, not a live accessor, and exists because the live one cannot
    // be re-read after the fact: `snapshotFired()` sets
    // `prev_observed_ts_us = observed_ts_us`, so from the moment a transition
    // fires `frame_delta_us()` reads `x - x == 0` until the next frame lands.
    // The trace step is recorded AFTER dispatch returns (`TestRunner::
    // onCaptured` cannot record earlier — it detects the transition by
    // comparing the pre/post-dispatch state), so the trace MUST read this
    // latch rather than the accessor. See `appendTimingJson`.
    //
    // 0 until the first transition fires, and 0 for that first transition
    // itself (it latches `frame_delta_us()`'s documented first-transition
    // sentinel — no prior fired frame to measure from).
    //
    // NOT for SCXML conds: a cond runs mid-dispatch, BEFORE `snapshotFired()`,
    // so this still holds the PREVIOUS transition's delta while the live
    // `frame_delta_us()` holds the current frame's. `cpp:captured.
    // frame_delta_us()` is the only correct form in a guard; this field is the
    // evidence-export mirror of what that guard read.
    //
    // For a TICK-driven trace step (`deadline_exceeded`, `pcap_frame_idx ==
    // -1`) no dispatch ran, so this still holds the last FRAME-driven fired
    // delta: "the last delta that actually decided something", paired with a
    // `pcap_frame_idx` of -1 that tells the reader no frame drove this step.
    // That is deliberate — the alternative (the live accessor) would report
    // the gap between an arbitrary non-firing frame and an unrelated earlier
    // transition, which is non-zero and meaningless.
    std::int64_t fired_frame_delta_us = 0;

    // Wall-clock (CLOCK_REALTIME epoch microseconds — the SAME domain as
    // `observed_ts_us`, which is the pcap `gettimeofday` arrival stamp) instant
    // the LISTEN WINDOW opened: stamped ONCE by `TestRunner::start()` right after
    // `kickStimulus` returns and before the SM is driven. This is NOT when the
    // kernel BPF capture began — that is armed earlier, before `kickStimulus`
    // (see test_command.cpp) — so a frame the DUT sent during stimulus may
    // already sit in the capture ring with an `observed_ts_us` BEFORE this stamp
    // (a negative raw delta, clamped to 0 below). 0 means "not stamped" (a
    // non-timing context, or a runner that never opened a window). Unlike
    // `observed_ts_us` it is NOT a per-frame value: every per-frame fill leaves
    // it untouched, so it stays the run's single listen-window reference.
    std::int64_t listen_window_open_ts_us = 0;

    std::int64_t frame_delta_us() const noexcept {
        if (prev_observed_ts_us == 0) {
            return 0;
        }
        return observed_ts_us - prev_observed_ts_us;
    }

    // "A transition fired on the current frame — remember it." The single
    // definition of the fired-frame bookkeeping every protocol's dispatch
    // helper runs under its `getCurrentState() != state_before` guard, in
    // place of the hand-repeated `prev_observed_ts_us = observed_ts_us` each
    // site used to inline. Owned by the base that owns the fields so the
    // latch can never be forgotten at a call site or drift out of order
    // against the assignment.
    //
    // ORDER IS LOAD-BEARING: `fired_frame_delta_us` latches the accessor
    // BEFORE the assignment invalidates it. Advancing `prev` first would make
    // the latch read `x - x == 0` — the exact defect this method exists to
    // make unrepresentable.
    //
    // Call ONLY when the SCXML actually transitioned on this frame, so
    // non-fired frames (filter mismatches, cyclic offers between two phase
    // boundaries) never pollute the gap. Contexts carrying extra
    // fired-transition landmarks (the SOME/IP `prev_sd_session_id` /
    // `prev_tp_more_segments`) snapshot those alongside this call.
    void snapshotFired() noexcept {
        fired_frame_delta_us = frame_delta_us();
        prev_observed_ts_us  = observed_ts_us;
    }

    // Microsecond gap from the listen-window-open instant to the current frame —
    // the measurement reference for "delay from the DUT's boot / re-activation,
    // or a tester-emitted stimulus, to its FIRST captured response", which
    // `frame_delta_us()` (frame-to-frame, 0 on the first transition) cannot
    // express. A case orders the reference event (an interface resume, a
    // FindService emit) as the last thing its `stimulus()` does, so window-open
    // approximates that event, and an SCXML cond reads
    // `cpp:captured.delta_from_listen_window_us()` against an `expected.*`
    // threshold (e.g. an initial-delay window).
    //
    // Returns 0 — the same "unmeasurable" sentinel `frame_delta_us()` uses for
    // the first transition — when either timestamp is unset, so a guard with a
    // non-zero lower bound fails closed on a missing reference. A negative raw
    // difference (a frame that reached the capture ring before the window opened,
    // i.e. the DUT responded during stimulus) is clamped to 0 — also fail-closed
    // for a `>= MIN` guard. This is a SEPARATE accessor: `frame_delta_us()`'s
    // first-transition-returns-0 contract — relied on by TCP RETRANSMISSION_TO,
    // DHCPv4 REACQUISITION, and the SD_BEHAVIOR offer-to-offer guards — is
    // deliberately left unchanged.
    std::int64_t delta_from_listen_window_us() const noexcept {
        return positiveGapFrom(listen_window_open_ts_us);
    }

    // Microsecond gap from an arbitrary anchor timestamp to this frame's observed
    // instant, with the shared fail-closed semantics: returns 0 when either stamp
    // is unset (0), and clamps a negative raw difference (anchor after the frame)
    // to 0 so a `>= MIN` guard fails closed. Defined ONCE so every anchored-delta
    // accessor — `delta_from_listen_window_us` here and the SOME/IP-SD
    // `delta_from_sd_start_us` on the derived context — shares the identical
    // guard+clamp and the semantics cannot drift across them.
    std::int64_t positiveGapFrom(std::int64_t anchor_ts_us) const noexcept {
        if (anchor_ts_us == 0 || observed_ts_us == 0) {
            return 0;
        }
        const std::int64_t d = observed_ts_us - anchor_ts_us;
        return d > 0 ? d : 0;
    }
};

}  // namespace tc8
