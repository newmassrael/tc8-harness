#pragma once

#include <cstdint>
#include <string>

namespace tc8 {

// Per-source frame accounting for one capture run — "was the wire observation
// underlying this verdict complete?".
//
// A verdict that measures an inter-frame gap anchors on the first frame of a
// kind it PROCESSED and treats it as the first frame the DUT SENT. Those are
// the same frame only while the capture is lossless: if the kernel ring dropped
// the early members of a burst, the anchor slides forward and every gap measured
// from it is short by an unknown amount — a false FAIL of a healthy DUT that
// leaves no trace of its own cause, because the evidence of the loss is exactly
// what was lost. These counters are that missing evidence, so a run can state
// whether it was in a position to measure at all.
//
// Deliberately a plain-data leaf carrying NO libpcap types: it crosses from the
// capture layer (which owns the `pcap_t`) to the trace/evidence layer, and the
// latter must not acquire a libpcap dependency to report a number.
struct CaptureStats {
    // The capture source these counters describe, so a multi-source run (a
    // second broadcast domain folded into one time-ordered stream) attributes
    // loss to the interface that suffered it rather than to the run as a whole.
    std::string iface;

    // False when the source cannot report counters at all — an offline replay
    // (a savefile has no ring to overflow), or a live handle whose `pcap_stats`
    // call failed. The counters below are then meaningless and MUST NOT be read
    // as zeroes: "no loss" and "no measurement" are different claims, and
    // collapsing them would recreate the very blind spot this type exists to
    // remove. Consumers report the tri-state (complete / lossy / unknown).
    bool available = false;

    // libpcap `ps_recv` — frames the capture accepted for this run.
    std::uint32_t frames_received = 0;

    // libpcap `ps_drop` — frames dropped because the kernel buffer had no room,
    // i.e. the reader fell behind. This is the counter that indicts a loaded,
    // parallel run: the 16 MB ring makes it rare, and "rare" is the problem,
    // because the runs where it bites are exactly the intermittent ones.
    std::uint32_t frames_dropped_ring = 0;

    // libpcap `ps_ifdrop` — frames dropped by the interface/driver before
    // libpcap saw them. Not maintained by every platform (it stays 0 where
    // unsupported), so a 0 here is weaker evidence than a 0 in the ring counter.
    std::uint32_t frames_dropped_iface = 0;

    // True only when the source measured AND lost something. Never true for an
    // unmeasured source: an unknown must not read as a loss, just as it must not
    // read as clean — callers that care about "unknown" check `available`.
    bool lostFrames() const {
        return available && (frames_dropped_ring != 0 || frames_dropped_iface != 0);
    }
};

}  // namespace tc8
