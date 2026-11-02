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

#include "tc8/testability/reactor.h"

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
    std::vector<int> ready;        // fds to report readable on the next poll()
    std::vector<int> write_ready;  // fds to report writable on the next poll()

    int poll(const int *read_fds, std::size_t read_n, const int *write_fds, std::size_t write_n,
             int /*timeout_ms*/, std::vector<int> &readable,
             std::vector<int> &writable) override {
        readable.clear();
        writable.clear();
        for (std::size_t i = 0; i < read_n; ++i) {
            for (const int r : ready) {
                if (read_fds[i] == r) {
                    readable.push_back(read_fds[i]);
                }
            }
        }
        for (std::size_t i = 0; i < write_n; ++i) {
            for (const int w : write_ready) {
                if (write_fds[i] == w) {
                    writable.push_back(write_fds[i]);
                }
            }
        }
        return static_cast<int>(readable.size() + writable.size());
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

// A read watch and a write watch on one fd fire on their own readiness only. A
// pending connect is watched for writable while a forward may watch the same fd for
// readable, so firing one for the other would read a socket that has nothing to say.
TEST(ReactorSingleThread, WriteWatchFiresOnWritableOnly) {
    FakeMux mux;
    tt::Reactor r{mux};
    r.open();

    constexpr int kFakeFd = 7;
    int reads = 0;
    int writes = 0;
    r.addWatch(kFakeFd, [&] { ++reads; });
    const tt::WatchId write_watch = r.addWriteWatch(kFakeFd, [&] { ++writes; });

    mux.ready = {kFakeFd};
    r.runOnce(/*max_wait_ms=*/0);
    EXPECT_EQ(reads, 1);
    EXPECT_EQ(writes, 0) << "readable must not fire the write watch";

    mux.ready.clear();
    mux.write_ready = {kFakeFd};
    r.runOnce(/*max_wait_ms=*/0);
    EXPECT_EQ(reads, 1) << "writable must not fire the read watch";
    EXPECT_EQ(writes, 1);

    r.removeWatch(write_watch);
    r.runOnce(/*max_wait_ms=*/0);
    EXPECT_EQ(writes, 1) << "a removed write watch stays quiet";

    r.close();
}

}  // namespace
