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
// transition: it is auto-snapshotted by each protocol's dispatch helper
// (`dispatchTcpFrame` / `dispatchUdpFrame` / `dispatchIcmpv4Frame` /
// `dispatchIpv4Frame` / `dispatchDhcpv4Frame`, the SOME/IP
// `SomeIpAnyBase::dispatch` hook, and inline in the ARP cases) ONLY when
// `getCurrentState()` advances, so non-fired frames between two state
// advances never pollute the gap.
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
        if (listen_window_open_ts_us == 0 || observed_ts_us == 0) {
            return 0;
        }
        const std::int64_t d = observed_ts_us - listen_window_open_ts_us;
        return d > 0 ? d : 0;
    }
};

}  // namespace tc8
