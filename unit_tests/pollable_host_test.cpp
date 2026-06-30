// Hermetic test of PollableHost (dut/dut_service/pollable_host.h): the DUT-side
// drain owner an extension adopts a pollable receiver into. Backs a fake pollable
// with a real non-blocking socketpair so the poll() + onReadable() drain path is
// exercised end-to-end on the loopback fd — no DUT, no vsomeip, no network.

#include <cstddef>
#include <cstdint>
#include <memory>

#include <fcntl.h>
#include <sys/socket.h>
#include <unistd.h>

#include <gtest/gtest.h>

#include "pollable_host.h"
#include "tc8/pollable_service.h"

namespace {

// A pollable over a borrowed fd that drains all available bytes on each onReadable,
// counting drains and bytes so the test can assert the host called it exactly when
// the fd was ready.
class CountingPollable : public tc8::IPollableService {
public:
    explicit CountingPollable(int fd) : fd_(fd) {}

    int pollFd() const override { return fd_; }

    void onReadable() override {
        std::uint8_t buf[64];
        for (;;) {
            const ssize_t n = ::read(fd_, buf, sizeof(buf));
            if (n <= 0) {
                break;  // EWOULDBLOCK (drained) or EOF
            }
            bytes += static_cast<std::size_t>(n);
        }
        ++drains;
    }

    int drains = 0;
    std::size_t bytes = 0;

private:
    int fd_;
};

// A connected non-blocking socket pair; closes both ends on destruction.
struct SocketPair {
    SocketPair() {
        EXPECT_EQ(::socketpair(AF_UNIX, SOCK_STREAM, 0, fds), 0);
        const int flags = ::fcntl(fds[0], F_GETFL, 0);
        ::fcntl(fds[0], F_SETFL, flags | O_NONBLOCK);
    }
    ~SocketPair() {
        if (fds[0] >= 0) {
            ::close(fds[0]);
        }
        if (fds[1] >= 0) {
            ::close(fds[1]);
        }
    }
    int readEnd() const { return fds[0]; }
    int writeEnd() const { return fds[1]; }
    void closeWriteEnd() {
        if (fds[1] >= 0) {
            ::close(fds[1]);
            fds[1] = -1;
        }
    }
    int fds[2] = {-1, -1};
};

}  // namespace

TEST(PollableHost, DrainsReadyServiceOnReadable) {
    SocketPair sp;
    tc8::dut::PollableHost host;
    auto pollable = std::make_unique<CountingPollable>(sp.readEnd());
    CountingPollable* probe = pollable.get();
    host.adoptPollable(std::move(pollable));

    // No data yet: poll times out, onReadable is not called.
    host.drainReady(10);
    EXPECT_EQ(probe->drains, 0);
    EXPECT_EQ(probe->bytes, 0u);

    // Data arrives: the next drain wakes on the ready fd and drains it.
    const std::uint8_t msg[3] = {0x11, 0x22, 0x33};
    ASSERT_EQ(::write(sp.writeEnd(), msg, sizeof(msg)), static_cast<ssize_t>(sizeof(msg)));
    host.drainReady(200);
    EXPECT_EQ(probe->drains, 1);
    EXPECT_EQ(probe->bytes, 3u);

    // Fully drained: a further drain times out without calling onReadable again.
    host.drainReady(10);
    EXPECT_EQ(probe->drains, 1);
}

TEST(PollableHost, SkipsServiceWithNegativeFd) {
    tc8::dut::PollableHost host;
    auto pollable = std::make_unique<CountingPollable>(-1);
    CountingPollable* probe = pollable.get();
    host.adoptPollable(std::move(pollable));

    // A service whose pollFd() is -1 is owned but never polled — the host must not
    // pass it to poll() (a -1 fd there is undefined) nor call onReadable.
    host.drainReady(5);
    EXPECT_EQ(probe->drains, 0);
}

TEST(PollableHost, EmptyHostJustWaits) {
    tc8::dut::PollableHost host;
    // No adopted service: drainReady is a bounded sleep that returns cleanly.
    host.drainReady(1);
    SUCCEED();
}

TEST(PollableHost, DrainsOnlyTheReadyServiceAmongMany) {
    SocketPair quiet;
    SocketPair active;
    tc8::dut::PollableHost host;
    auto quiet_pollable = std::make_unique<CountingPollable>(quiet.readEnd());
    auto active_pollable = std::make_unique<CountingPollable>(active.readEnd());
    CountingPollable* quiet_probe = quiet_pollable.get();
    CountingPollable* active_probe = active_pollable.get();
    host.adoptPollable(std::move(quiet_pollable));
    host.adoptPollable(std::move(active_pollable));

    const std::uint8_t msg[2] = {0xAB, 0xCD};
    ASSERT_EQ(::write(active.writeEnd(), msg, sizeof(msg)), static_cast<ssize_t>(sizeof(msg)));
    host.drainReady(200);

    // Only the service whose fd had data is drained; the quiet one is left untouched.
    EXPECT_EQ(active_probe->drains, 1);
    EXPECT_EQ(active_probe->bytes, 2u);
    EXPECT_EQ(quiet_probe->drains, 0);
}

TEST(PollableHost, DropsServiceOnPeerHangup) {
    SocketPair sp;
    tc8::dut::PollableHost host;
    auto pollable = std::make_unique<CountingPollable>(sp.readEnd());
    CountingPollable* probe = pollable.get();
    host.adoptPollable(std::move(pollable));

    // Drain the buffered data while the peer is still open — the service stays polled.
    const std::uint8_t msg[2] = {0x55, 0x66};
    ASSERT_EQ(::write(sp.writeEnd(), msg, sizeof(msg)), static_cast<ssize_t>(sizeof(msg)));
    host.drainReady(200);
    EXPECT_EQ(probe->bytes, 2u);
    EXPECT_EQ(host.adoptedCount(), 1u);

    // Close the peer: the read end latches POLLHUP, which a non-blocking read cannot
    // clear, so poll() would report it every pass. The next drain must drop the dead
    // service rather than busy-spin re-calling onReadable (the D1 guard). The dropped
    // service is destroyed here — `probe` dangles afterward, so it is not touched.
    sp.closeWriteEnd();
    host.drainReady(200);
    EXPECT_EQ(host.adoptedCount(), 0u);

    // Nothing left to poll → bounded sleep, returns cleanly (no spin).
    host.drainReady(1);
    EXPECT_EQ(host.adoptedCount(), 0u);
    (void)probe;
}
