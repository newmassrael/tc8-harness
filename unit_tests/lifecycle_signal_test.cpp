// Unit test of the warm-suspendInterface lifecycle channel
// (dut/dut_service/lifecycle_signal.h) against a FAKE Waker — no eventfd, no running DUT.
// Covers the cross-thread contract the DUT relies on: post() enqueues and wakes; drain()
// returns the queued events in FIFO order and clears them; a suspend/re-offer burst is
// delivered losslessly (not coalesced); and pollFd() forwards the Waker's fd. This is the
// replacement for resume_edge_test — the polled counter + edge-detector it exercised is
// gone (resolved TD-13).

#include <memory>

#include <gtest/gtest.h>

#include "lifecycle_signal.h"
#include "testability/io_multiplexer.h"

namespace {

// A Waker that records signal()/drain() calls instead of touching an fd, so the channel's
// wake/drain contract is testable without a real eventfd.
class FakeWaker final : public tc8::testability::Waker {
public:
    int pollFd() const override { return kFd; }
    void signal() override { ++signals; }
    void drain() override { ++drains; }

    static constexpr int kFd = 4242;
    int signals = 0;
    int drains = 0;
};

using tc8::dut::LifecycleEvent;
using tc8::dut::LifecycleSignal;

}  // namespace

TEST(LifecycleSignal, PollFdForwardsTheWakerFd) {
    LifecycleSignal sig(std::make_unique<FakeWaker>());
    EXPECT_EQ(sig.pollFd(), FakeWaker::kFd);
}

TEST(LifecycleSignal, DrainWithNothingQueuedIsEmptyButStillDrainsTheWaker) {
    auto waker = std::make_unique<FakeWaker>();
    FakeWaker* w = waker.get();
    LifecycleSignal sig(std::move(waker));

    EXPECT_TRUE(sig.drain().empty());
    EXPECT_EQ(w->drains, 1);   // the fd is drained even when the queue is empty
    EXPECT_EQ(w->signals, 0);  // nothing posted
}

TEST(LifecycleSignal, PostEnqueuesAndWakes) {
    auto waker = std::make_unique<FakeWaker>();
    FakeWaker* w = waker.get();
    LifecycleSignal sig(std::move(waker));

    sig.post(LifecycleEvent::Suspend);
    EXPECT_EQ(w->signals, 1);  // each post wakes the loop

    const auto events = sig.drain();
    ASSERT_EQ(events.size(), 1u);
    EXPECT_EQ(events[0], LifecycleEvent::Suspend);
}

TEST(LifecycleSignal, BurstIsDeliveredInFifoOrderAndLosslessly) {
    auto waker = std::make_unique<FakeWaker>();
    FakeWaker* w = waker.get();
    LifecycleSignal sig(std::move(waker));

    // A suspend/re-offer cycle posted before the loop drains: both events survive (no
    // coalescing) and arrive in post order — Suspend before its paired Reactivate.
    sig.post(LifecycleEvent::Suspend);
    sig.post(LifecycleEvent::Reactivate);
    EXPECT_EQ(w->signals, 2);

    const auto events = sig.drain();
    ASSERT_EQ(events.size(), 2u);
    EXPECT_EQ(events[0], LifecycleEvent::Suspend);
    EXPECT_EQ(events[1], LifecycleEvent::Reactivate);
}

TEST(LifecycleSignal, DrainClearsSoEventsAreNotRedelivered) {
    LifecycleSignal sig(std::make_unique<FakeWaker>());

    sig.post(LifecycleEvent::Reactivate);
    EXPECT_EQ(sig.drain().size(), 1u);
    EXPECT_TRUE(sig.drain().empty());  // consumed once, not again
}
