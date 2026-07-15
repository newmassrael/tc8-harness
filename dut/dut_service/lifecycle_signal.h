#pragma once

#include <cstdint>
#include <memory>
#include <mutex>
#include <utility>
#include <vector>

#include "tc8/testability/io_multiplexer.h"  // tc8::testability::Waker

namespace tc8::dut {

// The warm-suspendInterface lifecycle transitions an extension is told about.
enum class LifecycleEvent : std::uint8_t {
    Suspend,     // a warm suspendInterface StopOffer — the service was de-offered
    Reactivate,  // the paired warm re-offer — the service is offered again
};

// Cross-thread lifecycle-event channel: the detached suspend thread post()s
// Suspend/Reactivate and wakes the DUT main loop through the repo's canonical Waker
// primitive (testability/io_multiplexer.h); the main loop drains the queued events on
// ITS thread (never the detached one) via the IPollableService seam it already folds
// into its poll set (PollableHost::drainReady), and dispatches the extension hooks.
//
// This SINGLE-SOURCES "signal a poll loop" on the Waker for every lifecycle transition,
// replacing the per-signal polled monotonic counter + edge-detector: the
// events are FIFO-ordered (Suspend before its paired Reactivate) and LOSSLESS (no
// coalescing of a burst into one fire), and the loop wakes PROMPTLY on the eventfd
// instead of noticing the change on its next tick poll.
//
// Held by dut_main as a shared_ptr and captured by COPY into the detached suspend
// closure (never the ServerRole `this`), so post() stays valid regardless of
// ServerRole's lifetime — the same discipline the polled counter used for its
// shared_ptr<atomic>. Enqueue-then-signal on post, drain-then-dequeue on the loop, so a
// post() racing a drain is never lost: it either lands in that batch or re-arms the fd
// for the next pass.
class LifecycleSignal {
public:
    explicit LifecycleSignal(std::unique_ptr<tc8::testability::Waker> waker)
        : waker_(std::move(waker)) {}

    // Any thread (the detached suspend closure): enqueue an event, then wake the loop.
    void post(LifecycleEvent ev) {
        {
            std::lock_guard<std::mutex> lock(mutex_);
            pending_.push_back(ev);
        }
        waker_->signal();
    }

    // The fd the DUT main loop folds into its poll set for a prompt wake.
    int pollFd() const { return waker_->pollFd(); }

    // Main-loop thread: consume the wake and return the events queued since the last
    // drain, in post order. Drains the Waker first so poll() stops reporting readiness;
    // the queue (not the eventfd counter) is the source of truth.
    std::vector<LifecycleEvent> drain() {
        waker_->drain();
        std::lock_guard<std::mutex> lock(mutex_);
        return std::exchange(pending_, {});
    }

private:
    std::unique_ptr<tc8::testability::Waker> waker_;
    std::mutex mutex_;
    std::vector<LifecycleEvent> pending_;
};

}  // namespace tc8::dut
