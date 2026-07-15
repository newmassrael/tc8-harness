#pragma once

#include <atomic>

#include "tc8/testability/io_multiplexer.h"

namespace tc8::dut::test {

// A Waker that records signal()/drain() calls instead of touching an fd, so the queue and
// dispatch logic built on the Waker interface are testable without a real eventfd. Counters
// are atomic so a test may signal() from several producer threads (the concurrent-post
// stress test) without a data race in the double itself. Shared by lifecycle_signal_test
// and lifecycle_dispatcher_test (one source of truth for the fake).
class FakeWaker final : public tc8::testability::Waker {
public:
    int pollFd() const override { return kFd; }
    void signal() override { signals.fetch_add(1, std::memory_order_relaxed); }
    void drain() override { drains.fetch_add(1, std::memory_order_relaxed); }

    static constexpr int kFd = 4242;
    std::atomic<int> signals{0};
    std::atomic<int> drains{0};
};

}  // namespace tc8::dut::test
