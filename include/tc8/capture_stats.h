#pragma once

#include <cstdint>
#include <string>
#include <vector>

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

    // --- Multicast delivery: the third way a capture can misrepresent the wire
    //
    // The counters above measure loss AFTER a frame reached this interface. A
    // frame an upstream snooping bridge pruned never reaches it, so it is
    // dropped by nothing here, truncated by nothing here, and leaves every
    // counter above at a clean zero. Measured on a WiFi hop: the DUT put 18 SD
    // frames on the wire and this source recorded `recv=0 drop=0 ifdrop=0`,
    // i.e. a capture that provably did not represent the wire reported itself
    // complete. Passive pcap emits no IGMP report, so a snooping bridge has no
    // reason to forward a group to us and the pruning is the DEFAULT there.
    //
    // Holding the membership is what removes that cause, and only then does
    // "we saw nothing" mean "the DUT sent nothing". These two fields are the
    // record of whether that precondition actually held, so an absence-based
    // pass can require it the same way it already requires no drop and no
    // truncation.
    //
    // Groups this source was asked to hold for the run — derived from the
    // case's own expectation surface, never configured separately. Empty means
    // the run needs no multicast to reason, and the question does not apply.
    std::vector<std::string> multicast_groups;

    // The subset of `multicast_groups` the kernel refused. Non-empty means the
    // run observed a wire it had NOT established it could hear.
    std::vector<std::string> multicast_groups_failed;

    // True when every group this source needed was actually joined. Vacuously
    // true when none were needed — unlike `available`, there is no unknown
    // state here: a join either succeeded or reported why it did not.
    bool multicastMembershipHeld() const {
        return multicast_groups_failed.empty();
    }
};

// --- Run-level predicates over every source a run captured on -------------
//
// These live next to the tri-state they read so "unknown is not clean" is
// stated ONCE. A verdict rule that re-derived it from `lostFrames()` alone
// would silently take the third state for the first: `lostFrames()` is false
// for an unmeasured source, which is the right answer to "did it lose frames?"
// and the WRONG answer to "was it complete?".

// True when some source PROVED loss. Never true for a source that could not
// measure — that one is unknown, not clean.
inline bool anySourceLostFrames(const std::vector<CaptureStats> &sources) {
    for (const CaptureStats &s : sources) {
        if (s.lostFrames()) {
            return true;
        }
    }
    return false;
}

// True only when EVERY source reported real counters. An empty list is false:
// no source reporting is an absence of evidence, not evidence of completeness —
// the same reason `available` exists at all.
inline bool everySourceMeasured(const std::vector<CaptureStats> &sources) {
    if (sources.empty()) {
        return false;
    }
    for (const CaptureStats &s : sources) {
        if (!s.available) {
            return false;
        }
    }
    return true;
}

// True when some source needed a multicast group it did not get. Reported
// separately from loss because the remedy is different in kind: a drop says the
// reader fell behind, an unheld group says the run was never in a position to
// hear the traffic at all.
inline bool anySourceMissingMulticastMembership(const std::vector<CaptureStats> &sources) {
    for (const CaptureStats &s : sources) {
        if (!s.multicastMembershipHeld()) {
            return true;
        }
    }
    return false;
}

// The claim an absence-based verdict needs: "the run observed the whole window
// on every source". Three independent halves, because there are three ways the
// claim fails: a frame the kernel DROPPED, a frame delivered but CUT SHORT
// (checked by the caller, which owns the dissector), and a frame the network
// never DELIVERED because we did not hold its group. The third is the one no
// counter can see after the fact, which is exactly why it is established up
// front and recorded rather than inferred here.
inline bool captureProvenComplete(const std::vector<CaptureStats> &sources) {
    return everySourceMeasured(sources) && !anySourceLostFrames(sources)
           && !anySourceMissingMulticastMembership(sources);
}

}  // namespace tc8
