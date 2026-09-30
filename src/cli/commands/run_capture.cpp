#include "cli/run_capture.h"

#include <thread>
#include <vector>

#include <poll.h>

#include "capture/pcap_source.h"
#include "cli/signal_handler.h"
#include "dissect/packet_pipeline.h"
#include "sce_integration/test_runner.h"
#include "tc8/pollable_service.h"

namespace tc8::cli {

sce::ICapturePump::Drained RunCapture::drain() {
    if (SignalGuard::stopRequested()) {
        return Drained{Status::kStopped, 0};
    }
    const int n = dispatchFrom(src_, dlt_);
    if (n == -2) {
        return Drained{Status::kEndOfCapture, 0};
    }
    if (n < 0) {
        error_ = std::string("dispatch error: ") + src_.lastError();
        return Drained{Status::kError, 0};
    }
    // §4.7.6.5 USAGE_01: drain the secondary source within the same pass so
    // frames arriving on TIface-1 interleave with primary-iface frames in the
    // order they hit the wire. The kernel ring is per-handle, so each call
    // picks up only its iface's queue; round-robin per pass is the simplest
    // serialiser, and the SCXML's time-ordered guards tolerate the ~20 ms
    // quanta cleanly.
    int n2 = 0;
    if (src2_ != nullptr) {
        n2 = dispatchFrom(*src2_, dlt2_);
        if (n2 == -2) {
            return Drained{Status::kEndOfCapture, static_cast<std::size_t>(n)};
        }
        if (n2 < 0) {
            error_ = std::string("dispatch error (secondary): ") + src2_->lastError();
            return Drained{Status::kError, static_cast<std::size_t>(n)};
        }
    }
    // Answer any pending ARP (and future background-service input) inline on
    // this thread — a tester-spoofed source IP the DUT is resolving gets its
    // Reply within this pass. Asked each time: a stimulus may adopt a service
    // part-way through.
    for (::tc8::IPollableService *svc : runner_.pollableServices()) {
        svc->onReadable();
    }
    return Drained{Status::kOk, static_cast<std::size_t>(n + n2)};
}

void RunCapture::waitForInput(std::chrono::milliseconds max) {
    std::vector<pollfd> pfds;
    const auto add = [&pfds](int fd) {
        if (fd >= 0) {
            pollfd pfd{};
            pfd.fd = fd;
            pfd.events = POLLIN;
            pfds.push_back(pfd);
        }
    };
    add(src_.selectableFd());
    if (src2_ != nullptr) {
        add(src2_->selectableFd());
    }
    for (::tc8::IPollableService *svc : runner_.pollableServices()) {
        add(svc->pollFd());
    }
    if (pfds.empty()) {
        std::this_thread::sleep_for(max);
        return;
    }
    // Readable, error or EINTR alike just return to the caller, which
    // re-drains; the return value needs no inspection.
    poll(pfds.data(), static_cast<nfds_t>(pfds.size()), static_cast<int>(max.count()));
}

int RunCapture::dispatchFrom(capture::PcapSource &source, int dlt) {
    return source.dispatch(
        /*max_frames=*/-1, [this, dlt](const pcap_pkthdr &hdr, const u_char *data) {
            int this_frame_idx = -1;
            if (dumper_ != nullptr) {
                pcap_dump(reinterpret_cast<u_char *>(dumper_), &hdr, data);
                this_frame_idx = next_pcap_frame_idx_++;
            }
            runner_.setNextPcapFrameIdx(this_frame_idx);
            pipeline_.processFrame(hdr, data, dlt);
        });
}

}  // namespace tc8::cli
