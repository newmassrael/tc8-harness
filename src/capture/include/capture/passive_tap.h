#pragma once

#include <atomic>
#include <functional>
#include <memory>
#include <thread>

#include <pcap/pcap.h>

#include "capture/pcap_source.h"

namespace tc8::capture {

// A read-only second look at an interface, on its own thread.
//
// The tester's capture (RunCapture) is read in step with the case: during a stimulus
// that does not await, nothing drains it, so a watcher of the live state stream sees
// the tester's own sends but none of the DUT's replies until the stimulus returns. A
// PassiveTap reads the same interface through a SEPARATE libpcap handle with its own
// kernel ring, handing each frame to a sink as the kernel delivers it.
//
// What it must never do, and how that is kept:
//   - It shares nothing with the capture the verdict rests on: its own handle, its own
//     ring, its own thread. A frame it drops, or a slow sink, costs the capture
//     nothing; the kernel copies each frame to every open handle independently.
//   - It reads and reports only. The sink is given the frame bytes to look at; there is
//     no path back into the runner, the held frames, the adopted services or the
//     state machine, so when any of those see traffic is unchanged.
//
// The handle is handed in already opened and filtered, so what to listen on stays the
// caller's decision (the same BPF as the capture, for lines that match the saved pcap).
class PassiveTap {
public:
    using FrameSink = std::function<void(const pcap_pkthdr &, const u_char *)>;

    // `source` is a live handle in non-blocking mode (PcapSource::openLive); an offline
    // source also works, for tests, and simply ends. `sink` runs on the tap's thread
    // (and once more on the caller's, from stop(), for the final drain).
    PassiveTap(std::unique_ptr<PcapSource> source, FrameSink sink);
    ~PassiveTap();
    PassiveTap(const PassiveTap &) = delete;
    PassiveTap &operator=(const PassiveTap &) = delete;

    void start();

    // Ends the thread, then drains what the kernel still holds for this handle, so
    // the last frames before the stop are not lost. Idempotent. After it returns the
    // sink is never called again.
    void stop();

private:
    void run();

    std::unique_ptr<PcapSource> source_;
    FrameSink                   sink_;
    std::atomic<bool>           stop_requested_{false};
    std::thread                 thread_;
    bool                        stopped_ = false;
};

}  // namespace tc8::capture
