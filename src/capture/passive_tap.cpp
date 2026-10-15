#include "capture/passive_tap.h"

#include <chrono>
#include <utility>

#include <poll.h>

namespace tc8::capture {

namespace {

// How long an idle wait lasts at most, which bounds how long stop() waits for the
// thread to notice the request.
constexpr std::chrono::milliseconds kIdleWait{20};

}  // namespace

PassiveTap::PassiveTap(std::unique_ptr<PcapSource> source, FrameSink sink)
    : source_(std::move(source)), sink_(std::move(sink)) {}

PassiveTap::~PassiveTap() {
    stop();
}

void PassiveTap::start() {
    thread_ = std::thread([this] { run(); });
}

void PassiveTap::stop() {
    if (stopped_) {
        return;
    }
    stopped_ = true;
    stop_requested_.store(true, std::memory_order_relaxed);
    if (thread_.joinable()) {
        thread_.join();
    }
    // The thread has gone; the handle is ours alone again. Frames that arrived while
    // it was waking up are still in the ring.
    source_->dispatch(/*max_frames=*/-1, sink_);
}

void PassiveTap::run() {
    while (!stop_requested_.load(std::memory_order_relaxed)) {
        if (source_->dispatch(/*max_frames=*/-1, sink_) > 0) {
            continue;
        }
        // Idle: wait for the kernel to signal a frame, or for the interval to pass.
        // An offline source has no fd to wait on; it is at its end, so a timed wait
        // is all that is left to do.
        const int fd = source_->selectableFd();
        if (fd >= 0) {
            pollfd p{fd, POLLIN, 0};
            ::poll(&p, 1, static_cast<int>(kIdleWait.count()));
        } else {
            std::this_thread::sleep_for(kIdleWait);
        }
    }
}

}  // namespace tc8::capture
