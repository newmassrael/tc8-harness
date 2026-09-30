#pragma once

#include <chrono>
#include <string>

#include <pcap/pcap.h>

#include "sce_integration/stimulus_observation.h"

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

private:
    // Evidence Export (Option 3): every frame appended to the saved pcap gets a
    // monotonic index, surfaced to the runner BEFORE pipeline.processFrame so the
    // resulting transition (if any) can be correlated back. -1 when there is no
    // dumper; a transition recorded at -1 surfaces as a verdict-decider-not-
    // retained note via the site walker.
    int dispatchFrom(capture::PcapSource &source, int dlt);

    capture::PcapSource     &src_;
    int                      dlt_;
    capture::PcapSource     *src2_;
    int                      dlt2_;
    pcap_dumper_t           *dumper_;
    dissect::PacketPipeline &pipeline_;
    sce::ITestRunner        &runner_;
    int                      next_pcap_frame_idx_ = 0;
    std::string              error_;
};

}  // namespace tc8::cli
