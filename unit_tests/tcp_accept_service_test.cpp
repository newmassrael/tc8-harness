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
#include <string>
#include <thread>
#include <utility>
#include <vector>

#include <gtest/gtest.h>

#include "stimulus/tcp_accept_service.h"
#include "stimulus/endpoint.h"
#include "stimulus/tx_observer.h"

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

// Records every report: what it was, under which step, and on which connection.
struct TxRecorder final : ITxObserver {
    struct Seen {
        std::string   transport;
        int           step;
        std::uint16_t dst_port;
        std::uint16_t src_port;
    };
    std::vector<Seen> seen;
    void onTx(const TxEvent &ev) override {
        seen.push_back({ev.transport, ev.spec_step, ev.dst_port, ev.src_port});
    }
    // The reports of one transport, in order.
    std::vector<Seen> of(const std::string &transport) const {
        std::vector<Seen> out;
        for (const Seen &s : seen) {
            if (s.transport == transport) out.push_back(s);
        }
        return out;
    }
};

// The tester's own port of a connected client socket.
std::uint16_t localPortOf(int fd) {
    sockaddr_in local{};
    socklen_t   len = sizeof(local);
    ::getsockname(fd, reinterpret_cast<sockaddr *>(&local), &len);
    return ntohs(local.sin_port);
}

}  // namespace

// The DUT's FIN, observed through the read the case makes, is reported once with both
// ends of the connection and the step the case is in; reading the EOF again is not a
// second close.
TEST(TcpConnection, ObservingTheFinByReadReportsTheCloseAckOnce) {
    TcpServer srv("lo", 0);
    ASSERT_TRUE(srv.valid());
    const int client = connectLoopbackClient(srv.port());
    ASSERT_GE(client, 0);
    const std::uint16_t client_port = localPortOf(client);
    auto conn = srv.acceptOne(1000ms);
    ASSERT_TRUE(conn.has_value());

    TxRecorder rec;
    setTxObserver(&rec);
    ::close(client);
    {
        TxSpecStep step(52);
        EXPECT_TRUE(conn->waitForPeerFin(1000ms));
        std::vector<std::uint8_t> scratch;
        EXPECT_EQ(conn->recv(scratch, 100ms), 0);  // EOF again
    }
    setTxObserver(nullptr);

    const auto got = rec.of("tcp_close_ack");
    ASSERT_EQ(got.size(), 1u);
    EXPECT_EQ(got[0].step, 52);
    EXPECT_EQ(got[0].dst_port, client_port);  // the DUT's end
    EXPECT_EQ(got[0].src_port, srv.port());   // the tester's end
}

// A connection the case holds and does not read still gets its FIN noticed, without a
// read: the bytes the DUT sent first stay unread, and noticing it twice reports once.
TEST(TcpConnection, ObservePeerCloseSeesTheFinWithoutReadingAnything) {
    TcpServer srv("lo", 0);
    ASSERT_TRUE(srv.valid());
    const int client = connectLoopbackClient(srv.port());
    ASSERT_GE(client, 0);
    auto conn = srv.acceptOne(1000ms);
    ASSERT_TRUE(conn.has_value());

    TxRecorder rec;
    setTxObserver(&rec);
    EXPECT_FALSE(conn->observePeerClose(53));  // the DUT is still there: nothing to report
    EXPECT_TRUE(rec.seen.empty());

    const std::uint8_t data[] = {0x11, 0x22, 0x33};
    ASSERT_EQ(::write(client, data, sizeof(data)), 3);
    ::close(client);
    std::this_thread::sleep_for(50ms);

    EXPECT_TRUE(conn->observePeerClose(53));
    EXPECT_TRUE(conn->observePeerClose(54));  // already noticed: no second report, no new step
    setTxObserver(nullptr);

    const auto got = rec.of("tcp_close_ack");
    ASSERT_EQ(got.size(), 1u);
    EXPECT_EQ(got[0].step, 53);
    EXPECT_EQ(rec.seen.size(), 1u);

    // Nothing was consumed: the bytes are still there, then the EOF.
    std::vector<std::uint8_t> bytes;
    EXPECT_EQ(conn->recv(bytes, 100ms), 3);
    EXPECT_EQ(bytes, (std::vector<std::uint8_t>{0x11, 0x22, 0x33}));
}

// A reset is not a FIN and nothing ACKed it, so it is not a close ack.
TEST(TcpConnection, AResetIsNotACloseAck) {
    TcpServer srv("lo", 0);
    ASSERT_TRUE(srv.valid());
    const int client = connectLoopbackClient(srv.port());
    ASSERT_GE(client, 0);
    auto conn = srv.acceptOne(1000ms);
    ASSERT_TRUE(conn.has_value());

    const linger abortive{1, 0};
    ASSERT_EQ(::setsockopt(client, SOL_SOCKET, SO_LINGER, &abortive, sizeof(abortive)), 0);
    ::close(client);
    std::this_thread::sleep_for(50ms);

    TxRecorder rec;
    setTxObserver(&rec);
    EXPECT_FALSE(conn->observePeerClose(53));
    setTxObserver(nullptr);
    EXPECT_TRUE(rec.seen.empty());
}

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

// The accept's SYN+ACK is reported with the step the service was given, on the
// connection the DUT opened; what the handler then sends over it is not that step.
TEST(TcpAcceptService, TheAcceptCarriesItsStepAndTheHandlersSendDoesNot) {
    struct Capture final : ITxObserver {
        struct Seen {
            std::string   transport;
            int           step;
            std::uint16_t dst_port;
            std::uint16_t src_port;
        };
        std::vector<Seen> seen;
        void onTx(const TxEvent &ev) override {
            seen.push_back({ev.transport, ev.spec_step, ev.dst_port, ev.src_port});
        }
    } capture;

    TcpAcceptService svc(
        "lo", 0, [](TcpConnection c) { c.send({0x01, 0x02}); }, /*accept_step=*/50);
    ASSERT_TRUE(svc.ok());
    const int client = connectLoopbackClient(svc.boundPort());
    ASSERT_GE(client, 0);
    sockaddr_in local{};
    socklen_t len = sizeof(local);
    ASSERT_EQ(::getsockname(client, reinterpret_cast<sockaddr *>(&local), &len), 0);

    setTxObserver(&capture);
    const bool accepted = pumpUntilAccepted(svc, 1);
    setTxObserver(nullptr);
    ::close(client);
    ASSERT_TRUE(accepted);

    ASSERT_EQ(capture.seen.size(), 2u);
    EXPECT_EQ(capture.seen[0].transport, "tcp_accept");
    EXPECT_EQ(capture.seen[0].step, 50);
    // The DUT's end is the destination; the tester's is the listener's port.
    EXPECT_EQ(capture.seen[0].dst_port, ntohs(local.sin_port));
    EXPECT_EQ(capture.seen[0].src_port, svc.boundPort());
    EXPECT_EQ(capture.seen[1].transport, "tcp");
    EXPECT_EQ(capture.seen[1].step, kNoSpecStep);
    EXPECT_EQ(capture.seen[1].src_port, svc.boundPort());
}

// A case that specifies only its reconnect tags only that accept: the first connection's
// SYN+ACK is no step of the procedure and must not carry one.
TEST(TcpAcceptService, TheStepIsChosenPerAcceptByItsIndex) {
    TcpAcceptService svc("lo", 0, [](TcpConnection) {}, acceptStepFrom(2, 56));
    ASSERT_TRUE(svc.ok());
    const int first = connectLoopbackClient(svc.boundPort());
    ASSERT_GE(first, 0);

    TxRecorder rec;
    setTxObserver(&rec);
    ASSERT_TRUE(pumpUntilAccepted(svc, 1));
    const int second = connectLoopbackClient(svc.boundPort());
    ASSERT_GE(second, 0);
    ASSERT_TRUE(pumpUntilAccepted(svc, 2));
    setTxObserver(nullptr);
    ::close(first);
    ::close(second);

    const auto got = rec.of("tcp_accept");
    ASSERT_EQ(got.size(), 2u);
    EXPECT_EQ(got[0].step, kNoSpecStep);
    EXPECT_EQ(got[1].step, 56);

    // The constant form still tags every accept, as it always did.
    TcpAcceptService every("lo", 0, [](TcpConnection) {}, /*accept_step=*/57);
    ASSERT_TRUE(every.ok());
    const int c = connectLoopbackClient(every.boundPort());
    ASSERT_GE(c, 0);
    TxRecorder rec2;
    setTxObserver(&rec2);
    ASSERT_TRUE(pumpUntilAccepted(every, 1));
    setTxObserver(nullptr);
    ::close(c);
    ASSERT_EQ(rec2.of("tcp_accept").size(), 1u);
    EXPECT_EQ(rec2.of("tcp_accept")[0].step, 57);
}

// The service does not keep the connections, so whoever does asks it to look at each; the
// FIN is reported under the service's close_step, not the step of the thread that asked.
TEST(TcpAcceptService, ObserveCloseReportsTheHeldConnectionsFinUnderItsCloseStep) {
    std::vector<TcpConnection> held;
    TcpAcceptService svc(
        "lo", 0, [&](TcpConnection c) { held.push_back(std::move(c)); },
        /*accept_step=*/kNoSpecStep, /*close_step=*/58);
    ASSERT_TRUE(svc.ok());
    const int client = connectLoopbackClient(svc.boundPort());
    ASSERT_GE(client, 0);
    ASSERT_TRUE(pumpUntilAccepted(svc, 1));
    ASSERT_EQ(held.size(), 1u);

    TxRecorder rec;
    setTxObserver(&rec);
    {
        TxSpecStep unrelated(99);  // a case scope on the thread that happens to ask
        EXPECT_FALSE(svc.observeClose(held[0]));  // not closed yet
        ::close(client);
        std::this_thread::sleep_for(50ms);
        EXPECT_TRUE(svc.observeClose(held[0]));
    }
    setTxObserver(nullptr);

    const auto got = rec.of("tcp_close_ack");
    ASSERT_EQ(got.size(), 1u);
    EXPECT_EQ(got[0].step, 58);
}

// The capture loop drains the services only after the stimulus returns, so a connection
// can be accepted long after the DUT opened it, and the DUT may have reset it by then.
// A reset socket no longer has a peer to ask (getpeername says ENOTCONN), but accept()
// itself returned the peer's address: the report must name the connection from that.
TEST(TcpAcceptService, AnAcceptOfAConnectionAlreadyResetStillNamesTheConnection) {
    struct Capture final : ITxObserver {
        std::vector<TxEvent> seen;
        void onTx(const TxEvent &ev) override { seen.push_back(ev); }
    } capture;

    TcpAcceptService svc("lo", 0, [](TcpConnection) {}, /*accept_step=*/51);
    ASSERT_TRUE(svc.ok());
    const int client = connectLoopbackClient(svc.boundPort());
    ASSERT_GE(client, 0);
    sockaddr_in local{};
    socklen_t len = sizeof(local);
    ASSERT_EQ(::getsockname(client, reinterpret_cast<sockaddr *>(&local), &len), 0);
    // Close with RST, while the connection still waits in the accept queue.
    const linger abortive{1, 0};
    ASSERT_EQ(::setsockopt(client, SOL_SOCKET, SO_LINGER, &abortive, sizeof(abortive)), 0);
    ::close(client);
    std::this_thread::sleep_for(50ms);

    setTxObserver(&capture);
    const bool accepted = pumpUntilAccepted(svc, 1);
    setTxObserver(nullptr);
    ASSERT_TRUE(accepted);

    ASSERT_EQ(capture.seen.size(), 1u);
    EXPECT_EQ(std::string(capture.seen[0].transport), "tcp_accept");
    EXPECT_EQ(capture.seen[0].spec_step, 51);
    EXPECT_EQ(capture.seen[0].dst_ip_be, htonl(INADDR_LOOPBACK));
    EXPECT_EQ(capture.seen[0].dst_port, ntohs(local.sin_port));
    EXPECT_EQ(capture.seen[0].src_port, svc.boundPort());
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
