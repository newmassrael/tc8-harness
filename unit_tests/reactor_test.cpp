#include <arpa/inet.h>

#include <atomic>
#include <chrono>
#include <cstdint>
#include <thread>

#include <gtest/gtest.h>

#include "tc8/net/socket_backend.h"
#include "tc8/linux_socket_backend.h"
#include "test_port_util.h"
#include "tc8/testability/reactor.h"

// The Reactor exercised in isolation against a real IoMultiplexer (the POSIX
// backend) with NO ProtocolServer and NO MiddlewareModule — the point of
// extracting it: the event loop (posted tasks, timers, fd watches, the waker) is
// reusable and unit-testable on its own, free of the testability protocol.

namespace {

namespace tt = tc8::testability;
using ms = std::chrono::milliseconds;

// Poll a predicate until true or a deadline — no fixed sleeps, so a loaded host
// cannot false-fail (the repo has a timing-flake history).
template <class Pred>
bool waitUntil(Pred p, ms timeout = ms{2000}) {
    const auto deadline = std::chrono::steady_clock::now() + timeout;
    while (std::chrono::steady_clock::now() < deadline) {
        if (p()) {
            return true;
        }
        std::this_thread::sleep_for(ms{2});
    }
    return p();
}

tc8::net::Endpoint loopback(std::uint16_t port) {
    return tc8::net::Endpoint{::htonl(INADDR_LOOPBACK), port};
}

TEST(Reactor, PostRunsTaskOnLoopThread) {
    tc8::dut::LinuxSocketBackend be;
    tt::Reactor r{be};
    r.start();

    std::atomic<bool> ran{false};
    std::thread::id loop_id;
    r.post([&] {
        loop_id = std::this_thread::get_id();
        ran = true;
    });
    EXPECT_TRUE(ran.load());                          // post() blocks until it ran
    EXPECT_NE(loop_id, std::this_thread::get_id());   // and it ran on the reactor thread
    r.stop();
}

TEST(Reactor, OneShotTimerFiresExactlyOnce) {
    tc8::dut::LinuxSocketBackend be;
    tt::Reactor r{be};
    r.start();

    std::atomic<int> fired{0};
    r.post([&] { r.armOnce(ms{10}, [&] { ++fired; }); });  // arm on the loop thread
    EXPECT_TRUE(waitUntil([&] { return fired.load() >= 1; }));
    std::this_thread::sleep_for(ms{60});
    EXPECT_EQ(fired.load(), 1);  // one-shot does not re-fire
    r.stop();
}

TEST(Reactor, PeriodicTimerFiresRepeatedlyUntilCancelled) {
    tc8::dut::LinuxSocketBackend be;
    tt::Reactor r{be};
    r.start();

    std::atomic<int> fired{0};
    tt::TimerId id{};
    r.post([&] { id = r.armEvery(ms{5}, [&] { ++fired; }); });
    EXPECT_TRUE(waitUntil([&] { return fired.load() >= 3; }));
    r.post([&] { r.cancel(id); });  // cancel on the loop thread
    const int after_cancel = fired.load();
    std::this_thread::sleep_for(ms{40});
    EXPECT_LE(fired.load(), after_cancel + 1);  // at most one in-flight fire after cancel
    r.stop();
}

TEST(Reactor, WatchFiresOnReadableFd) {
    tc8::dut::LinuxSocketBackend be;
    tt::Reactor r{be};
    r.start();

    const int rx = be.createUdp();
    ASSERT_GE(rx, 0);
    constexpr std::uint16_t kPort = 31971;
    TC8_STATIC_ASSERT_TEST_PORT(kPort);
    ASSERT_TRUE(be.bindV4(rx, 0, kPort));

    std::atomic<int> got{0};
    r.post([&] {
        r.addWatch(rx, [&] {
            std::uint8_t buf[32];
            tc8::net::Endpoint src{};
            if (be.recvFromV4(rx, buf, sizeof(buf), src) > 0) {
                ++got;
            }
        });
    });

    const int tx = be.createUdp();
    ASSERT_GE(tx, 0);
    const std::uint8_t payload[] = {0x42};
    be.sendToV4(tx, payload, sizeof(payload), loopback(kPort));

    EXPECT_TRUE(waitUntil([&] { return got.load() >= 1; }))
        << "reactor did not dispatch the readable watch";
    r.stop();
    be.closeFd(tx);
    be.closeFd(rx);
}

TEST(Reactor, StopRunsFinalTaskThenJoinsAndIsIdempotent) {
    tc8::dut::LinuxSocketBackend be;
    tt::Reactor r{be};
    r.start();

    std::atomic<bool> final_ran{false};
    r.stop([&] { final_ran = true; });
    EXPECT_TRUE(final_ran.load());
    r.stop();  // second stop is a no-op — must not hang or crash
}

// Caller-driven (single-task) mode: no owned thread. open() makes the calling
// thread the loop thread, so timers and watches are armed directly (no post()),
// and the caller pumps runOnce() itself — the shape a bare-metal / RTOS task uses.
TEST(Reactor, CallerDrivenPumpServicesTimersAndWatchesWithNoOwnedThread) {
    tc8::dut::LinuxSocketBackend be;
    tt::Reactor r{be};
    r.open();  // this thread IS the loop thread — no reactor thread is spawned

    int fired = 0;  // plain int: single-threaded by construction in this mode
    r.armOnce(ms{1}, [&] { ++fired; });

    const int rx = be.createUdp();
    ASSERT_GE(rx, 0);
    constexpr std::uint16_t kPort = 31973;
    TC8_STATIC_ASSERT_TEST_PORT(kPort);
    ASSERT_TRUE(be.bindV4(rx, 0, kPort));
    int got = 0;
    r.addWatch(rx, [&] {
        std::uint8_t buf[32];
        tc8::net::Endpoint src{};
        if (be.recvFromV4(rx, buf, sizeof(buf), src) > 0) {
            ++got;
        }
    });

    const int tx = be.createUdp();
    ASSERT_GE(tx, 0);
    const std::uint8_t payload[] = {0x42};
    be.sendToV4(tx, payload, sizeof(payload), loopback(kPort));

    // Pump from this task until both are serviced or a wall-clock deadline — bound
    // by time, not iteration count, so a loaded host cannot false-fail (the repo's
    // waitUntil convention); the reactor waits ~1 ms per poll for the 1 ms timer.
    const auto deadline = std::chrono::steady_clock::now() + ms{2000};
    while (std::chrono::steady_clock::now() < deadline && (fired == 0 || got == 0)) {
        r.runOnce(/*max_wait_ms=*/5);
    }
    EXPECT_EQ(fired, 1) << "one-shot timer serviced by the caller-driven pump";
    EXPECT_GE(got, 1) << "readable watch serviced by the caller-driven pump";

    r.close();  // no thread to join
    be.closeFd(tx);
    be.closeFd(rx);
}

// A watch handler that removes its OWN watch must be safe — the dispatch copies the
// stored std::function before invoking it, so erasing the watch (freeing that
// function) mid-call cannot pull the running lambda out from under itself. This is
// the pattern the unified server's self-terminating workers and END_TEST rely on.
TEST(Reactor, WatchMayRemoveItselfFromWithinHandler) {
    tc8::dut::LinuxSocketBackend be;
    tt::Reactor r{be};
    r.open();

    const int rx = be.createUdp();
    ASSERT_GE(rx, 0);
    constexpr std::uint16_t kPort = 31975;
    TC8_STATIC_ASSERT_TEST_PORT(kPort);
    ASSERT_TRUE(be.bindV4(rx, 0, kPort));

    int fires = 0;
    tt::WatchId wid = tt::kNoWatch;
    wid = r.addWatch(rx, [&] {
        std::uint8_t buf[32];
        tc8::net::Endpoint src{};
        be.recvFromV4(rx, buf, sizeof(buf), src);
        ++fires;
        r.removeWatch(wid);  // self-remove mid-handler — must not crash or re-fire
    });

    const int tx = be.createUdp();
    ASSERT_GE(tx, 0);
    const std::uint8_t payload[] = {0x1};
    be.sendToV4(tx, payload, sizeof(payload), loopback(kPort));
    be.sendToV4(tx, payload, sizeof(payload), loopback(kPort));  // watch is gone by now

    const auto deadline = std::chrono::steady_clock::now() + ms{1000};
    while (std::chrono::steady_clock::now() < deadline && fires == 0) {
        r.runOnce(5);
    }
    for (int i = 0; i < 20; ++i) {  // extra pumps: a removed watch must not fire again
        r.runOnce(2);
    }
    EXPECT_EQ(fires, 1) << "self-removed watch fires exactly once, no crash";

    r.close();
    be.closeFd(tx);
    be.closeFd(rx);
}

}  // namespace
