// Tester-as-TCP-server accept surface (server-role topology). Drives TcpServer /
// TcpConnection over a loopback round-trip — accept + peer capture, server-side
// send, client-bytes recv, graceful peer-FIN observation, and multi-accept — with
// no privilege and no DUT. The kernel owns the TCP state machine; these tests pin
// the thin BSD-socket wrapper behaviour the reliable-transport cases depend on.

#include <arpa/inet.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <unistd.h>

#include <chrono>
#include <cstdint>
#include <utility>
#include <vector>

#include <gtest/gtest.h>

#include "stimulus/tcp_server.h"

namespace tc8::stimulus {
namespace {

using namespace std::chrono_literals;

// Connect a loopback TCP client to 127.0.0.1:`port`. Each TcpServer binds an
// ephemeral port (constructed with 0) and reports it via port(), so the tests are
// collision-proof on a busy host. Returns the connected fd (caller closes) or -1.
int connectLoopbackClient(std::uint16_t port) {
    const int fd = ::socket(AF_INET, SOCK_STREAM, 0);
    if (fd < 0) {
        return -1;
    }
    sockaddr_in a{};
    a.sin_family = AF_INET;
    a.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    a.sin_port = htons(port);
    if (::connect(fd, reinterpret_cast<sockaddr *>(&a), sizeof(a)) != 0) {
        ::close(fd);
        return -1;
    }
    return fd;
}

}  // namespace

TEST(TcpServer, AcceptCapturesPeerAndServerSendDelivers) {
    TcpServer srv("lo", 0);  // ephemeral port, read back via port()
    ASSERT_TRUE(srv.valid());

    const int client = connectLoopbackClient(srv.port());
    ASSERT_GE(client, 0);

    auto conn = srv.acceptOne(1000ms);
    ASSERT_TRUE(conn.has_value());
    EXPECT_TRUE(conn->valid());
    // Peer is loopback; the port is the client's ephemeral source port.
    EXPECT_EQ(conn->peer().ipv4_be, htonl(INADDR_LOOPBACK));
    EXPECT_NE(conn->peer().port, 0u);

    // 4b: server send → client receives the exact bytes.
    const std::vector<std::uint8_t> payload{0xDE, 0xAD, 0xBE, 0xEF};
    ASSERT_EQ(conn->send(payload), 0);
    std::uint8_t buf[16] = {};
    const ssize_t n = ::read(client, buf, sizeof(buf));
    ASSERT_EQ(n, 4);
    EXPECT_EQ(std::vector<std::uint8_t>(buf, buf + n), payload);

    ::close(client);
}

TEST(TcpServer, RecvReadsClientBytesThenObservesFin) {
    TcpServer srv("lo", 0);  // ephemeral port, read back via port()
    ASSERT_TRUE(srv.valid());
    const int client = connectLoopbackClient(srv.port());
    ASSERT_GE(client, 0);
    auto conn = srv.acceptOne(1000ms);
    ASSERT_TRUE(conn.has_value());

    // Client → server recv.
    const std::uint8_t req[] = {0x01, 0x02, 0x03};
    ASSERT_EQ(::write(client, req, sizeof(req)), 3);
    std::vector<std::uint8_t> got;
    const int r = conn->recv(got, 1000ms);
    ASSERT_EQ(r, 3);
    EXPECT_EQ(got, (std::vector<std::uint8_t>{0x01, 0x02, 0x03}));

    // 4c: client closes → the server observes the peer FIN.
    ::close(client);
    EXPECT_TRUE(conn->waitForPeerFin(1000ms));
}

TEST(TcpServer, WaitForFinDrainsPendingDataThenObservesFin) {
    TcpServer srv("lo", 0);  // ephemeral port, read back via port()
    ASSERT_TRUE(srv.valid());
    const int client = connectLoopbackClient(srv.port());
    ASSERT_GE(client, 0);
    auto conn = srv.acceptOne(1000ms);
    ASSERT_TRUE(conn.has_value());

    // Client sends data and immediately closes — waitForPeerFin must drain the
    // pending bytes (its r > 0 branch) and still see the FIN, without a prior recv.
    const std::uint8_t data[] = {0x55, 0x66, 0x77};
    ASSERT_EQ(::write(client, data, sizeof(data)), 3);
    ::close(client);
    EXPECT_TRUE(conn->waitForPeerFin(1000ms));
}

TEST(TcpServer, FinWaitTimesOutWhilePeerStaysOpen) {
    TcpServer srv("lo", 0);  // ephemeral port, read back via port()
    ASSERT_TRUE(srv.valid());
    const int client = connectLoopbackClient(srv.port());
    ASSERT_GE(client, 0);
    auto conn = srv.acceptOne(1000ms);
    ASSERT_TRUE(conn.has_value());

    // Peer stays open (no close) → no FIN within the short window. This is also
    // the 4e blackhole shape: accept + hold without answering.
    EXPECT_FALSE(conn->waitForPeerFin(100ms));
    ::close(client);
}

TEST(TcpServer, MultiAcceptTracksDistinctPeers) {
    TcpServer srv("lo", 0);  // ephemeral port, read back via port()
    ASSERT_TRUE(srv.valid());

    // Interleave connect/accept so the backlog-1 listener never queues two
    // pending connections at once (the two-instance accept shape).
    const int c1 = connectLoopbackClient(srv.port());
    ASSERT_GE(c1, 0);
    auto a = srv.acceptOne(1000ms);
    ASSERT_TRUE(a.has_value());

    const int c2 = connectLoopbackClient(srv.port());
    ASSERT_GE(c2, 0);
    auto b = srv.acceptOne(1000ms);
    ASSERT_TRUE(b.has_value());

    // Two live connections from two distinct client source ports.
    EXPECT_NE(a->peer().port, b->peer().port);

    ::close(c1);
    ::close(c2);
}

TEST(TcpServer, AcceptTimesOutWithNoClient) {
    TcpServer srv("lo", 0);  // ephemeral port, read back via port()
    ASSERT_TRUE(srv.valid());
    EXPECT_FALSE(srv.acceptOne(50ms).has_value());
}

TEST(TcpConnection, MoveTransfersFdOwnership) {
    TcpServer srv("lo", 0);  // ephemeral port, read back via port()
    ASSERT_TRUE(srv.valid());
    const int client = connectLoopbackClient(srv.port());
    ASSERT_GE(client, 0);
    auto conn = srv.acceptOne(1000ms);
    ASSERT_TRUE(conn.has_value());

    const int fd = conn->fd();
    TcpConnection moved = std::move(*conn);
    EXPECT_EQ(moved.fd(), fd);
    EXPECT_FALSE(conn->valid());  // moved-from connection is emptied (no double close).
    ::close(client);
}

}  // namespace tc8::stimulus
