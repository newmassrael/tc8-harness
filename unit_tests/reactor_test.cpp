#include <arpa/inet.h>

#include <atomic>
#include <chrono>
#include <cstdint>
#include <thread>

#include <gtest/gtest.h>

#include "net/socket_backend.h"
#include "posix_socket_backend.h"
#include "testability/reactor.h"

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
    tc8::dut::PosixSocketBackend be;
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
    tc8::dut::PosixSocketBackend be;
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
    tc8::dut::PosixSocketBackend be;
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
    tc8::dut::PosixSocketBackend be;
    tt::Reactor r{be};
    r.start();

    const int rx = be.createUdp();
    ASSERT_GE(rx, 0);
    constexpr std::uint16_t kPort = 39971;
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
    tc8::dut::PosixSocketBackend be;
    tt::Reactor r{be};
    r.start();

    std::atomic<bool> final_ran{false};
    r.stop([&] { final_ran = true; });
    EXPECT_TRUE(final_ran.load());
    r.stop();  // second stop is a no-op — must not hang or crash
}

}  // namespace
