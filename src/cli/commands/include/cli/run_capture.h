#pragma once

#include <chrono>
#include <cstddef>
#include <string>
#include <vector>

#include <pcap/pcap.h>

#include "sce_integration/stimulus_observation.h"
#include "tc8/link_outage_tracker.h"

namespace tc8::capture {
class PcapSource;
}
namespace tc8::dissect {
class PacketPipeline;
}
namespace tc8::sce {
class ITestRunner;
}

namespace tc8::cli {

// The run's capture as seen by everything that reads it: the one path by which a
// frame leaves a capture source, is appended to the saved pcap under the next
// index, and goes through the packet pipeline to the runner. Both the capture loop
// and a stimulus awaiting an observation (ICapturePump) drain it, so a frame read
// early for a stimulus is recorded exactly as the loop would have recorded it —
// same pcap index, same pipeline state, same withholding of control traffic.
//
// Every drain also services the run's adopted background services, so a service
// answers while a stimulus awaits as well as inside the window
// (tc8/pollable_service.h states that contract; run_capture_test pins it).
class RunCapture final : public sce::ICapturePump {
public:
    RunCapture(capture::PcapSource &src, int dlt, capture::PcapSource *src2, int dlt2,
               pcap_dumper_t *dumper, dissect::PacketPipeline &pipeline,
               sce::ITestRunner &runner)
        : src_(src), dlt_(dlt), src2_(src2), dlt2_(dlt2), dumper_(dumper),
          pipeline_(pipeline), runner_(runner) {}

    Drained drain() override;

    // Block up to `max` in poll() on the capture fd(s) plus every background
    // service's fd, returning the instant one is readable, so a frame arriving
    // mid-wait is dispatched within ~1 ms rather than after the full quantum. An
    // empty set (offline source, no services) degrades to a plain sleep.
    void waitForInput(std::chrono::milliseconds max) override;

    const std::string &error() const {
        return error_;
    }
    // The intervals during which the primary (`source` 0) or secondary (1) source's
    // link carried no traffic, as each drain observed it (CaptureStats::link_outages).
    // While a link is down its source cannot deliver anything, and a dispatch that
    // fails then is that outage, not a failed capture: the drain goes on polling
    // and the source delivers again once the link is back.
    const std::vector<::tc8::LinkOutage> &linkOutages(std::size_t source) const {
        return link_[source].outages();
    }

    // Make the saved pcap followable while the run is going: flush it to disk at
    // most once per `interval`, and only when frames were appended since the last
    // flush. The default (never called) leaves the stdio buffer to fill and flush
    // on its own, exactly as before. A time bound rather than a flush per frame
    // keeps a write syscall off every frame of the capture loop; the saved file's
    // contents and indices are unaffected either way, only WHEN they reach the disk.
    // Checked once per drain(), so the bound is `interval` plus one loop quantum.
    void followPcap(std::chrono::milliseconds interval) {
        pcap_flush_interval_ = interval;
    }

private:
    void flushPcapIfDue();

    // Evidence Export (Option 3): every frame appended to the saved pcap gets a
    // monotonic index, surfaced to the runner BEFORE pipeline.processFrame so the
    // resulting transition (if any) can be correlated back. -1 when there is no
    // dumper; a transition recorded at -1 surfaces as a verdict-decider-not-
    // retained note via the site walker.
    int dispatchFrom(capture::PcapSource &source, int dlt);
    // Dispatch `source`, observing its link before and, on a failure, after: a
    // failure while the link is down is an outage and counts as no frames.
    int dispatchObservingLink(capture::PcapSource &source, int dlt, ::tc8::LinkOutageTracker &link);

    capture::PcapSource     &src_;
    int                      dlt_;
    capture::PcapSource     *src2_;
    int                      dlt2_;
    pcap_dumper_t           *dumper_;
    dissect::PacketPipeline &pipeline_;
    sce::ITestRunner        &runner_;
    int                      next_pcap_frame_idx_ = 0;
    std::string              error_;
    ::tc8::LinkOutageTracker link_[2];
    // followPcap(): 0 = off. `pcap_dirty_` is set by a dump and cleared by a flush.
    std::chrono::milliseconds             pcap_flush_interval_{0};
    std::chrono::steady_clock::time_point pcap_last_flush_{};
    bool                                  pcap_dirty_ = false;
};

}  // namespace tc8::cli
