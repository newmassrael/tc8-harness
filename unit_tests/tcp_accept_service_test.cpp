// TcpAcceptService — the autonomous TCP-accept IPollableService adapter. Drives
// it over a loopback round-trip: a client connects at an arbitrary point and the
// service accepts it from inside the capture-loop drain (onReadable), captures
// the peer, and the handler can answer or hold the connection — with no privilege
// and no DUT. Mirrors tcp_server_test's loopback harness; this layer adds the
// non-blocking, fold-into-the-drain accept that the synchronous TcpServer path
// does not cover.

#include <arpa/inet.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <unistd.h>

#include <chrono>
#include <cstdint>
#include <thread>
#include <utility>
#include <vector>

#include <gtest/gtest.h>

#include "stimulus/tcp_accept_service.h"
#include "stimulus/endpoint.h"

namespace tc8::stimulus {
namespace {

using namespace std::chrono_literals;

// Connect a loopback TCP client to 127.0.0.1:`port`. Returns the connected fd
// (caller closes) or -1. Same helper shape as tcp_server_test.
int connectLoopbackClient(std::uint16_t port) {
    const int fd = ::socket(AF_INET, SOCK_STREAM, 0);
    if (fd < 0) {
        return -1;
    }
    sockaddr_in a{};
    a.sin_family      = AF_INET;
    a.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    a.sin_port        = htons(port);
    if (::connect(fd, reinterpret_cast<sockaddr *>(&a), sizeof(a)) != 0) {
        ::close(fd);
        return -1;
    }
    return fd;
}

// Pump the service's drain (onReadable) up to ~1 s until it has accepted
// `target` connections — models the capture loop calling onReadable() each
// iteration. Returns true once the count is reached.
bool pumpUntilAccepted(TcpAcceptService &svc, std::uint64_t target) {
    for (int i = 0; i < 100 && svc.accepted() < target; ++i) {
        svc.onReadable();
        std::this_thread::sleep_for(10ms);
    }
    return svc.accepted() >= target;
}

}  // namespace

TEST(TcpAcceptService, AcceptsAutonomousConnectAndCapturesPeer) {
    Endpoint captured{};
    int handler_calls = 0;
    TcpAcceptService svc("lo", 0, [&](TcpConnection c) {
        captured = c.peer();
        ++handler_calls;
        // c destructs at the end of the callback (graceful close).
    });
    ASSERT_TRUE(svc.ok());
    ASSERT_NE(svc.boundPort(), 0u);
    EXPECT_GE(svc.pollFd(), 0);

    const int client = connectLoopbackClient(svc.boundPort());
    ASSERT_GE(client, 0);

    ASSERT_TRUE(pumpUntilAccepted(svc, 1));
    EXPECT_EQ(svc.accepted(), 1u);
    EXPECT_EQ(handler_calls, 1);
    EXPECT_EQ(captured.ipv4_be, htonl(INADDR_LOOPBACK));
    EXPECT_NE(captured.port, 0u);  // the client's ephemeral source port.

    ::close(client);
}

TEST(TcpAcceptService, HandlerDeliversBytesOverAcceptedConnection) {
    const std::vector<std::uint8_t> payload{0x11, 0x22, 0x33, 0x44};
    TcpAcceptService svc("lo", 0, [&](TcpConnection c) { c.send(payload); });
    ASSERT_TRUE(svc.ok());

    const int client = connectLoopbackClient(svc.boundPort());
    ASSERT_GE(client, 0);

    ASSERT_TRUE(pumpUntilAccepted(svc, 1));
    std::uint8_t buf[16] = {};
    const ssize_t n = ::read(client, buf, sizeof(buf));
    ASSERT_EQ(n, 4);
    EXPECT_EQ(std::vector<std::uint8_t>(buf, buf + n), payload);

    ::close(client);
}

TEST(TcpAcceptService, HandlerCanHoldConnectionPastCallbackForBlackhole) {
    // The blackhole shape: the handler MOVES the accepted connection into
    // longer-lived storage instead of letting it close, so the DUT's connection
    // stays open and unanswered. Assert the held connection is still valid after
    // the callback returned.
    std::vector<TcpConnection> held;
    TcpAcceptService svc("lo", 0, [&](TcpConnection c) { held.push_back(std::move(c)); });
    ASSERT_TRUE(svc.ok());

    const int client = connectLoopbackClient(svc.boundPort());
    ASSERT_GE(client, 0);

    ASSERT_TRUE(pumpUntilAccepted(svc, 1));
    ASSERT_EQ(held.size(), 1u);
    EXPECT_TRUE(held[0].valid());  // not closed at callback exit — held open.

    // No bytes were sent and the connection is still open: a non-blocking client
    // read sees no FIN (would-block), i.e. the peer is held, not closed.
    std::uint8_t buf[4] = {};
    const ssize_t n = ::recv(client, buf, sizeof(buf), MSG_DONTWAIT);
    EXPECT_EQ(n, -1);  // EAGAIN/EWOULDBLOCK — open and silent.

    ::close(client);
}

TEST(TcpAcceptService, AcceptsSuccessiveConnectsTrackingDistinctPeers) {
    std::vector<std::uint16_t> peer_ports;
    TcpAcceptService svc("lo", 0,
                         [&](TcpConnection c) { peer_ports.push_back(c.peer().port); });
    ASSERT_TRUE(svc.ok());

    // Interleave connect/accept so the backlog-1 listener never holds two pending
    // connections at once (the two-instance accept shape, like the DUT opening a
    // second reliable connection later in the window).
    const int c1 = connectLoopbackClient(svc.boundPort());
    ASSERT_GE(c1, 0);
    ASSERT_TRUE(pumpUntilAccepted(svc, 1));

    const int c2 = connectLoopbackClient(svc.boundPort());
    ASSERT_GE(c2, 0);
    ASSERT_TRUE(pumpUntilAccepted(svc, 2));

    ASSERT_EQ(peer_ports.size(), 2u);
    EXPECT_NE(peer_ports[0], peer_ports[1]);  // distinct client source ports.

    ::close(c1);
    ::close(c2);
}

TEST(TcpAcceptService, DrainsMultiplePendingInOneOnReadable) {
    int handler_calls = 0;
    TcpAcceptService svc("lo", 0, [&](TcpConnection) { ++handler_calls; });
    ASSERT_TRUE(svc.ok());

    // Two DUT connects queue together before any drain (the service's deeper
    // backlog holds both).
    const int c1 = connectLoopbackClient(svc.boundPort());
    const int c2 = connectLoopbackClient(svc.boundPort());
    ASSERT_GE(c1, 0);
    ASSERT_GE(c2, 0);

    // Let both loopback handshakes settle into the accept queue, then a SINGLE
    // onReadable() must drain BOTH — the while-loop body runs more than once,
    // the drain-all behaviour the one-accept-per-call tests do not exercise.
    std::this_thread::sleep_for(100ms);
    svc.onReadable();
    EXPECT_EQ(svc.accepted(), 2u);
    EXPECT_EQ(handler_calls, 2);

    ::close(c1);
    ::close(c2);
}

TEST(TcpAcceptService, NoConnectLeavesAcceptCountZero) {
    TcpAcceptService svc("lo", 0, [](TcpConnection) {});
    ASSERT_TRUE(svc.ok());
    // Drain a few times with no client connecting — stays at zero, never blocks.
    for (int i = 0; i < 5; ++i) {
        svc.onReadable();
    }
    EXPECT_EQ(svc.accepted(), 0u);
}

TEST(TcpAcceptService, BadInterfaceReportsNotOk) {
    TcpAcceptService svc("tc8-no-such-if", 0, [](TcpConnection) {});
    EXPECT_FALSE(svc.ok());
    EXPECT_EQ(svc.pollFd(), -1);  // skipped by the capture loop.
    // Draining a failed service is a safe no-op.
    svc.onReadable();
    EXPECT_EQ(svc.accepted(), 0u);
}

}  // namespace tc8::stimulus
