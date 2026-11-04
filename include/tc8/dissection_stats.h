#pragma once

#include <cstdint>
#include <optional>
#include <string>

namespace tc8 {

// What became of every frame the dissector was handed in one run — the half of
// "was the observation complete?" that the capture counters (capture_stats.h)
// cannot answer, because it happens AFTER the capture delivered the frame.
//
// A frame the capture delivered can still fail to reach a verdict in three ways,
// and each must leave a count, because a frame that vanishes without one turns a
// reply that was on the wire into "no reply":
//
//   truncated      the capture kept fewer bytes than the frame had, so it is
//                  refused rather than decoded short (PacketPipeline);
//   undissectable  the bytes are all there and the decoder could not read them;
//   consumer fault the decoder read them and the code it handed the event to (the
//                  case's state machine) failed on it.
//
// Measured on an embedded target (2026-11-04): its Echo Reply to a request whose
// IPv4 options end with EOL and zero padding was on the wire 122 us after the
// request; the decoder refused the reply's options area, the frame was dropped with
// no trace, and three cases reported `fail` for "no reply" on a capture that held
// the reply.
//
// The first two are observation gaps: an absence-based verdict on a run that has
// one is unproven (docs/verdict_policy.md Section 2.1, H2), exactly as with a frame
// the kernel dropped. The third is the harness's own fault and outranks the verdict.
//
// A plain-data leaf with no libpcap or libtins type, for the reason CaptureStats is
// one: it crosses from the dissector to the verdict and evidence layers.
struct DissectionStats {
    // Frames handed to the dissector, in capture order. A frame's 0-based position in
    // this count is its index in the saved pcap, which receives every frame in the
    // same order before it is dissected (and a replay reads them back in it).
    std::uint64_t frames_seen = 0;

    std::uint64_t frames_truncated = 0;

    // Every undissectable frame, whoever sent it.
    std::uint64_t frames_undissectable = 0;
    // Those that could have been the DUT's: the Ethernet source is the DUT's MAC, or
    // the run named no DUT MAC to tell. The tester sends malformed frames on purpose
    // (a header the DUT must discard) and the capture sees its own stimulus too; the
    // tester knows what it sent, so an unreadable copy of it is no observation gap.
    std::uint64_t frames_undissectable_possibly_dut = 0;
    // The first of those: its 0-based index (see frames_seen) and what the decoder
    // said, so the frame can be opened in the saved pcap directly.
    std::optional<std::uint64_t> first_undissectable_frame;
    std::string first_undissectable_reason;

    std::uint64_t consumer_faults = 0;
    std::optional<std::uint64_t> first_consumer_fault_frame;
    std::string first_consumer_fault_reason;

    // True when no frame that could carry the DUT's behaviour was lost to the
    // dissector: none refused as truncated, none of the DUT's unreadable. Consumer
    // faults are not part of it: they are not a gap in what was observed but a
    // failure to act on it, and they decide the verdict on their own.
    bool observationComplete() const noexcept {
        return frames_truncated == 0 && frames_undissectable_possibly_dut == 0;
    }
};

}  // namespace tc8
