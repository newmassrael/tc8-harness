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

// A pollable over a borrowed fd that drains all available bytes on each onReadable.
// Counts drains and bytes into CALLER-OWNED externals so the totals survive the
// host dropping (and destroying) the pollable on a peer hangup.
class CountingPollable : public tc8::IPollableService {
public:
    CountingPollable(int fd, int* drains, std::size_t* bytes)
        : fd_(fd), drains_(drains), bytes_(bytes) {}

    int pollFd() const override { return fd_; }

    void onReadable() override {
        std::uint8_t buf[64];
        for (;;) {
            const ssize_t n = ::read(fd_, buf, sizeof(buf));
            if (n <= 0) {
                break;  // EWOULDBLOCK (drained) or EOF
            }
            *bytes_ += static_cast<std::size_t>(n);
        }
        ++*drains_;
    }

private:
    int fd_;
    int* drains_;
    std::size_t* bytes_;
};

// A connected non-blocking socket pair; closes both ends on destruction.
// closeWriteEnd() hangs up the peer so the read end latches POLLHUP.
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
    int drains = 0;
    std::size_t bytes = 0;
    host.adoptPollable(std::make_unique<CountingPollable>(sp.readEnd(), &drains, &bytes));

    // No data yet: poll times out, onReadable is not called.
    host.drainReady(10);
    EXPECT_EQ(drains, 0);
    EXPECT_EQ(bytes, 0u);

    // Data arrives: the next drain wakes on the ready fd and drains it.
    const std::uint8_t msg[3] = {0x11, 0x22, 0x33};
    ASSERT_EQ(::write(sp.writeEnd(), msg, sizeof(msg)), static_cast<ssize_t>(sizeof(msg)));
    host.drainReady(200);
    EXPECT_EQ(drains, 1);
    EXPECT_EQ(bytes, 3u);

    // Fully drained: a further drain times out without calling onReadable again.
    host.drainReady(10);
    EXPECT_EQ(drains, 1);
}

TEST(PollableHost, SkipsServiceWithNegativeFd) {
    tc8::dut::PollableHost host;
    int drains = 0;
    std::size_t bytes = 0;
    host.adoptPollable(std::make_unique<CountingPollable>(-1, &drains, &bytes));

    // A service whose pollFd() is -1 is owned but never polled — the host must not
    // pass it to poll() (a -1 fd there is undefined) nor call onReadable.
    host.drainReady(5);
    EXPECT_EQ(drains, 0);
    EXPECT_EQ(host.adoptedCount(), 1u);  // still owned, just not polled
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
    int dq = 0, da = 0;
    std::size_t bq = 0, ba = 0;
    host.adoptPollable(std::make_unique<CountingPollable>(quiet.readEnd(), &dq, &bq));
    host.adoptPollable(std::make_unique<CountingPollable>(active.readEnd(), &da, &ba));

    const std::uint8_t msg[2] = {0xAB, 0xCD};
    ASSERT_EQ(::write(active.writeEnd(), msg, sizeof(msg)), static_cast<ssize_t>(sizeof(msg)));
    host.drainReady(200);

    // Only the service whose fd had data is drained; the quiet one is left untouched.
    EXPECT_EQ(da, 1);
    EXPECT_EQ(ba, 2u);
    EXPECT_EQ(dq, 0);
}

TEST(PollableHost, DropsServiceOnPeerHangupAfterDrain) {
    SocketPair sp;
    tc8::dut::PollableHost host;
    int drains = 0;
    std::size_t bytes = 0;
    host.adoptPollable(std::make_unique<CountingPollable>(sp.readEnd(), &drains, &bytes));

    // Drain the buffered data while the peer is still open — the service stays polled.
    const std::uint8_t msg[2] = {0x55, 0x66};
    ASSERT_EQ(::write(sp.writeEnd(), msg, sizeof(msg)), static_cast<ssize_t>(sizeof(msg)));
    host.drainReady(200);
    EXPECT_EQ(bytes, 2u);
    EXPECT_EQ(host.adoptedCount(), 1u);

    // Close the peer: the read end latches POLLHUP, which a non-blocking read cannot
    // clear, so poll() would report it every pass. The next drain must drop the dead
    // service rather than busy-spin re-calling onReadable.
    sp.closeWriteEnd();
    host.drainReady(200);
    EXPECT_EQ(host.adoptedCount(), 0u);

    // Nothing left to poll → bounded sleep, returns cleanly (no spin).
    host.drainReady(1);
    EXPECT_EQ(host.adoptedCount(), 0u);
}

TEST(PollableHost, DrainsDataAndDropsHangupOnSamePass) {
    SocketPair sp;
    tc8::dut::PollableHost host;
    int drains = 0;
    std::size_t bytes = 0;
    host.adoptPollable(std::make_unique<CountingPollable>(sp.readEnd(), &drains, &bytes));

    // Buffer data, THEN close the peer: the read end now reports POLLIN | POLLHUP in
    // a single poll. drainReady must drain the buffered bytes (POLLIN) AND drop the
    // hung-up service (POLLHUP) on the same pass — not lose the data nor spin.
    const std::uint8_t msg[4] = {0xDE, 0xAD, 0xBE, 0xEF};
    ASSERT_EQ(::write(sp.writeEnd(), msg, sizeof(msg)), static_cast<ssize_t>(sizeof(msg)));
    sp.closeWriteEnd();
    host.drainReady(200);
    EXPECT_EQ(drains, 1);                 // onReadable ran on the drop pass
    EXPECT_EQ(bytes, 4u);                 // and drained the buffered bytes
    EXPECT_EQ(host.adoptedCount(), 0u);   // then the service was dropped
}

TEST(PollableHost, DropsMultipleDeadServicesInOnePass) {
    SocketPair a;
    SocketPair b;
    tc8::dut::PollableHost host;
    int da = 0, db = 0;
    std::size_t ba = 0, bb = 0;
    host.adoptPollable(std::make_unique<CountingPollable>(a.readEnd(), &da, &ba));
    host.adoptPollable(std::make_unique<CountingPollable>(b.readEnd(), &db, &bb));
    EXPECT_EQ(host.adoptedCount(), 2u);

    // Hang up both peers: both read ends latch POLLHUP, so one drain pass must drop
    // BOTH services (exercises the dead-set removal with more than one entry).
    a.closeWriteEnd();
    b.closeWriteEnd();
    host.drainReady(200);
    EXPECT_EQ(host.adoptedCount(), 0u);
}
