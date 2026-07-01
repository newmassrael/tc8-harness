// Unit test of the warm-suspendInterface lifecycle channel
// (dut/dut_service/lifecycle_signal.h). SCOPE (honest): the single-threaded cases below
// verify the QUEUE contract — post enqueues + wakes, drain returns events in FIFO order and
// clears them, a burst is not coalesced, pollFd forwards the Waker's fd — against a FakeWaker
// (the eventfd side-channel is substituted; its wake/level-triggered readiness is covered by
// the testability Reactor's use of the same primitive). The final case adds a CONCURRENT
// producer/consumer stress that pins the losslessness the mutex+queue provides under real
// thread contention. This replaces resume_edge_test (the polled counter it exercised is gone
// — resolved TD-13).

#include <atomic>
#include <cstddef>
#include <thread>
#include <vector>

#include <gtest/gtest.h>

#include "fake_waker.h"
#include "lifecycle_signal.h"

namespace {

using tc8::dut::LifecycleEvent;
using tc8::dut::LifecycleSignal;
using tc8::dut::test::FakeWaker;

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
    EXPECT_EQ(w->drains.load(), 1);   // the fd is drained even when the queue is empty
    EXPECT_EQ(w->signals.load(), 0);  // nothing posted
}

TEST(LifecycleSignal, PostEnqueuesAndWakes) {
    auto waker = std::make_unique<FakeWaker>();
    FakeWaker* w = waker.get();
    LifecycleSignal sig(std::move(waker));

    sig.post(LifecycleEvent::Suspend);
    EXPECT_EQ(w->signals.load(), 1);  // each post wakes the loop

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
    EXPECT_EQ(w->signals.load(), 2);

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

// Concurrency contract: many producer threads post() while a consumer drain()s in parallel;
// every posted event must be delivered exactly once (none lost to a post/drain race, none
// duplicated). This exercises the mutex+queue under real contention — the losslessness the
// design promises and the single-threaded cases above cannot show.
TEST(LifecycleSignal, LosslessUnderConcurrentPostAndDrain) {
    constexpr int kProducers = 8;
    constexpr int kPerProducer = 5000;
    constexpr std::size_t kTotal = static_cast<std::size_t>(kProducers) * kPerProducer;

    LifecycleSignal sig(std::make_unique<FakeWaker>());
    std::atomic<bool> producers_done{false};
    std::vector<LifecycleEvent> collected;  // touched only by the consumer thread
    collected.reserve(kTotal);

    std::thread consumer([&] {
        while (!producers_done.load(std::memory_order_acquire)) {
            for (const auto ev : sig.drain()) collected.push_back(ev);
        }
        for (const auto ev : sig.drain()) collected.push_back(ev);  // final sweep after join
    });

    std::vector<std::thread> producers;
    producers.reserve(kProducers);
    for (int p = 0; p < kProducers; ++p) {
        producers.emplace_back([&] {
            for (int i = 0; i < kPerProducer; ++i) sig.post(LifecycleEvent::Suspend);
        });
    }
    for (auto& t : producers) t.join();
    producers_done.store(true, std::memory_order_release);
    consumer.join();

    EXPECT_EQ(collected.size(), kTotal);  // nothing lost, nothing duplicated
}
