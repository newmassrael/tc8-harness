// The reactor's single-task build — compiled with -DTC8_REACTOR_SINGLE_THREAD, so
// <thread>/<mutex>/<future> are excluded and start()/stop()/cross-thread post()
// are compiled out. On a hosted toolchain this stands in for the bare-metal / RTOS
// target whose libstdc++ is --disable-threads: if this TU compiles and runs, the
// core has no residual dependency on threading primitives. It drives the loop only
// through the caller-driven entry (open / runOnce / close), against an in-TU fake
// IoMultiplexer so nothing else in the binary includes reactor.h (no ODR clash with
// the default, threaded reactor used by the rest of the suite).

#include <chrono>
#include <cstddef>
#include <memory>
#include <vector>

#include <gtest/gtest.h>

#include "testability/reactor.h"

#ifndef TC8_REACTOR_SINGLE_THREAD
#error "reactor_single_thread_test must be built with -DTC8_REACTOR_SINGLE_THREAD"
#endif

namespace {

namespace tt = tc8::testability;
using ms = std::chrono::milliseconds;

// A trivial multiplexer: no waker (single-task never wakes cross-thread), and poll()
// reports whichever fds the test has marked ready. Header-only deps, so the test
// links nothing but GTest.
class FakeMux final : public tt::IoMultiplexer {
public:
    std::vector<int> ready;  // fds to report readable on the next poll()

    int poll(const int *fds, std::size_t n, int /*timeout_ms*/,
             std::vector<int> &readable) override {
        readable.clear();
        for (std::size_t i = 0; i < n; ++i) {
            for (const int r : ready) {
                if (fds[i] == r) {
                    readable.push_back(fds[i]);
                }
            }
        }
        return static_cast<int>(readable.size());
    }
    std::unique_ptr<tt::Waker> createWaker() override { return nullptr; }
};

// Timers and fd watches are serviced by the caller-driven pump with no threading
// primitives compiled in.
TEST(ReactorSingleThread, TimerAndWatchServicedWithoutThreads) {
    FakeMux mux;
    tt::Reactor r{mux};
    r.open();  // single-task: no thread, no waker, no affinity id

    int fired = 0;
    r.armOnce(ms{0}, [&] { ++fired; });  // due immediately
    r.runOnce(/*max_wait_ms=*/0);
    EXPECT_EQ(fired, 1) << "one-shot timer fired on the caller-driven pump";

    int got = 0;
    constexpr int kFakeFd = 7;
    r.addWatch(kFakeFd, [&] { ++got; });
    mux.ready = {kFakeFd};  // the next poll() reports it readable
    r.runOnce(/*max_wait_ms=*/0);
    EXPECT_GE(got, 1) << "readable watch dispatched on the caller-driven pump";

    r.close();
    EXPECT_EQ(fired, 1);  // the one-shot did not re-fire
}

}  // namespace
