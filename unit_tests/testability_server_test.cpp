#include <arpa/inet.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <unistd.h>

#include <cstdint>
#include <vector>

#include <gtest/gtest.h>

#include "sce_integration/dut_control.h"
#include "stimulus/testability_client.h"
#include "tc8/testability_protocol.h"
#include "testability_server.h"

// Server-side integration: drive the real DUT-side TestabilityServer (which is
// vsomeip-independent — a hand-rolled SOME/IP endpoint over a plain socket)
// with the real tester-side client wrappers over loopback. This exercises the
// GENERAL lifecycle, the UDP CREATE_AND_BIND/CLOSE_SOCKET path (guarding the
// socktype refactor), and the full TCP active-open lifecycle
// (CREATE_AND_BIND + CONNECT + SEND_DATA + CLOSE_SOCKET) end to end.

namespace tc8 {
namespace {

namespace tp = ::tc8::testability;

// A high, uncommon port so the hermetic server bind does not collide with a
// canonical-port (30700) tc8-dut a developer may have running.
constexpr std::uint16_t kTestPort = 39701;

stimulus::TestabilityConfig loopbackConfig() {
    stimulus::TestabilityConfig cfg;
    cfg.dut_ip_be = ::htonl(INADDR_LOOPBACK);
    cfg.dut_port = kTestPort;
    return cfg;
}

class TestabilityServerTest : public ::testing::Test {
protected:
    void SetUp() override { ASSERT_TRUE(server_.start(kTestPort)); }
    void TearDown() override { server_.stop(); }

    dut::TestabilityServer server_;
};

TEST_F(TestabilityServerTest, GeneralLifecycleRoundTrips) {
    const auto cfg = loopbackConfig();
    const auto v = stimulus::testabilityGetVersion(cfg);
    ASSERT_TRUE(v.has_value());
    EXPECT_EQ(v->major, tp::kVersionMajor);
    EXPECT_EQ(v->minor, tp::kVersionMinor);
    EXPECT_EQ(v->patch, tp::kVersionPatch);

    EXPECT_TRUE(stimulus::testabilityStartTest(cfg).eok());
    EXPECT_TRUE(stimulus::testabilityEndTest(cfg, /*tc_id=*/1, "server-test").eok());
}

// The socktype refactor must keep the UDP CREATE_AND_BIND/CLOSE_SOCKET path
// working (a SOCK_DGRAM socket created, then closed).
TEST_F(TestabilityServerTest, UdpCreateAndCloseStillWork) {
    const auto cfg = loopbackConfig();
    std::vector<std::uint8_t> cb;
    cb.push_back(0x01);              // doBind = true
    tp::appendU16(cb, 0xFFFF);       // localPort = PORT_ANY
    tp::appendIpv4Addr(cb, 0);       // localAddr = any
    const auto cb_resp = stimulus::testabilityCall(cfg, tp::kGidUdp, tp::kPidCreateAndBind, cb);
    ASSERT_TRUE(cb_resp.eok());
    ASSERT_EQ(cb_resp.dat.size(), 2u);
    const std::uint16_t sid =
        static_cast<std::uint16_t>((cb_resp.dat[0] << 8) | cb_resp.dat[1]);
    EXPECT_TRUE(stimulus::testabilityCloseSocket(cfg, tp::kGidUdp, sid).eok());
}

// Full TCP active-open loop against a tester-side listener: CONNECT must drive
// the DUT into an ESTABLISHED connection the tester observes via accept(), and
// SEND_DATA must deliver bytes the tester reads back on that connection.
TEST_F(TestabilityServerTest, TcpActiveOpenAndSendDataObservable) {
    const auto cfg = loopbackConfig();

    // Tester listener on 127.0.0.1:ephemeral — the CONNECT destination.
    const int lfd = ::socket(AF_INET, SOCK_STREAM, 0);
    ASSERT_GE(lfd, 0);
    int on = 1;
    ::setsockopt(lfd, SOL_SOCKET, SO_REUSEADDR, &on, sizeof(on));
    sockaddr_in la{};
    la.sin_family = AF_INET;
    la.sin_addr.s_addr = ::htonl(INADDR_LOOPBACK);
    la.sin_port = 0;
    ASSERT_EQ(::bind(lfd, reinterpret_cast<sockaddr *>(&la), sizeof(la)), 0);
    ASSERT_EQ(::listen(lfd, 1), 0);
    socklen_t ll = sizeof(la);
    ASSERT_EQ(::getsockname(lfd, reinterpret_cast<sockaddr *>(&la), &ll), 0);
    const std::uint16_t listen_port = ntohs(la.sin_port);
    timeval tv{};
    tv.tv_sec = 2;
    ::setsockopt(lfd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));

    // CREATE_AND_BIND (TCP) -> CONNECT to the tester listener.
    const auto sock = stimulus::testabilityCreateAndBind(cfg, tp::kGidTcp, /*do_bind=*/false,
                                                         /*local_port=*/0xFFFF,
                                                         /*local_addr_be=*/0);
    ASSERT_TRUE(sock.has_value());
    const auto co = stimulus::testabilityTcpConnect(cfg, *sock, listen_port,
                                                    ::htonl(INADDR_LOOPBACK));
    EXPECT_TRUE(co.eok());

    sockaddr_in peer{};
    socklen_t pl = sizeof(peer);
    const int afd = ::accept(lfd, reinterpret_cast<sockaddr *>(&peer), &pl);
    EXPECT_GE(afd, 0) << "DUT CONNECT did not reach ESTABLISHED (accept timed out)";

    // SEND_DATA (TCP): bytes flow over the established connection.
    const std::vector<std::uint8_t> body = {'T', 'C', '8'};
    const auto sd = stimulus::testabilityTcpSendData(cfg, *sock, /*total_len=*/3,
                                                     /*flags=*/0, body);
    EXPECT_TRUE(sd.eok());
    if (afd >= 0) {
        ::setsockopt(afd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
        std::uint8_t buf[16];
        const ssize_t n = ::recv(afd, buf, sizeof(buf), 0);
        ASSERT_EQ(n, 3);
        EXPECT_EQ(buf[0], 'T');
        EXPECT_EQ(buf[1], 'C');
        EXPECT_EQ(buf[2], '8');
        ::close(afd);
    }
    ::close(lfd);

    EXPECT_TRUE(stimulus::testabilityCloseSocket(cfg, tp::kGidTcp, *sock).eok());
}

// SEND_DATA totalLen repeats the data up to the requested length (PRS_TPSP §6.10).
TEST_F(TestabilityServerTest, TcpSendDataRepeatsUpToTotalLen) {
    const auto cfg = loopbackConfig();

    const int lfd = ::socket(AF_INET, SOCK_STREAM, 0);
    ASSERT_GE(lfd, 0);
    int on = 1;
    ::setsockopt(lfd, SOL_SOCKET, SO_REUSEADDR, &on, sizeof(on));
    sockaddr_in la{};
    la.sin_family = AF_INET;
    la.sin_addr.s_addr = ::htonl(INADDR_LOOPBACK);
    la.sin_port = 0;
    ASSERT_EQ(::bind(lfd, reinterpret_cast<sockaddr *>(&la), sizeof(la)), 0);
    ASSERT_EQ(::listen(lfd, 1), 0);
    socklen_t ll = sizeof(la);
    ASSERT_EQ(::getsockname(lfd, reinterpret_cast<sockaddr *>(&la), &ll), 0);
    const std::uint16_t listen_port = ntohs(la.sin_port);

    const auto sock = stimulus::testabilityCreateAndBind(cfg, tp::kGidTcp, false, 0xFFFF, 0);
    ASSERT_TRUE(sock.has_value());
    ASSERT_TRUE(stimulus::testabilityTcpConnect(cfg, *sock, listen_port,
                                                ::htonl(INADDR_LOOPBACK))
                    .eok());
    sockaddr_in peer{};
    socklen_t pl = sizeof(peer);
    const int afd = ::accept(lfd, reinterpret_cast<sockaddr *>(&peer), &pl);
    ASSERT_GE(afd, 0);

    // data = {AB}, totalLen = 4 -> four AB bytes on the wire.
    const std::vector<std::uint8_t> body = {0xAB};
    ASSERT_TRUE(stimulus::testabilityTcpSendData(cfg, *sock, /*total_len=*/4, 0, body).eok());

    timeval tv{};
    tv.tv_sec = 2;
    ::setsockopt(afd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
    std::uint8_t buf[16];
    ssize_t got = 0;
    while (got < 4) {
        const ssize_t n = ::recv(afd, buf + got, sizeof(buf) - got, 0);
        if (n <= 0) break;
        got += n;
    }
    ASSERT_EQ(got, 4);
    for (int i = 0; i < 4; ++i) {
        EXPECT_EQ(buf[i], 0xABu);
    }
    ::close(afd);
    ::close(lfd);
    EXPECT_TRUE(stimulus::testabilityCloseSocket(cfg, tp::kGidTcp, *sock).eok());
}

// CONNECT to a port with no listener must fail (bounded, not hang) and not
// stall later requests on the single server thread.
TEST_F(TestabilityServerTest, TcpConnectToDeadPortReturnsError) {
    const auto cfg = loopbackConfig();
    const auto sock = stimulus::testabilityCreateAndBind(cfg, tp::kGidTcp, false, 0xFFFF, 0);
    ASSERT_TRUE(sock.has_value());
    // Port 1 on loopback: nothing listening -> connection refused.
    const auto co = stimulus::testabilityTcpConnect(cfg, *sock, /*dest_port=*/1,
                                                    ::htonl(INADDR_LOOPBACK),
                                                    /*timeout_ms=*/1500);
    EXPECT_TRUE(co.ok);              // the SP itself round-tripped
    EXPECT_NE(co.rid, tp::kRidEOk);  // but reported a non-success result

    // The server thread is still responsive afterwards.
    EXPECT_TRUE(stimulus::testabilityCloseSocket(cfg, tp::kGidTcp, *sock).eok());
    EXPECT_TRUE(stimulus::testabilityStartTest(cfg).eok());
}

// Full passive-open loop: bind a DUT listen socket, LISTEN_AND_ACCEPT, connect
// to it from the tester, and confirm the DUT emits the accept Event with the
// new socket id and the tester's port/address.
TEST_F(TestabilityServerTest, TcpListenAndAcceptEmitsEventOnConnect) {
    const auto cfg = loopbackConfig();
    constexpr std::uint16_t kListenPort = 39811;

    // CREATE_AND_BIND (TCP) with a bound, known listen port.
    std::vector<std::uint8_t> cb;
    cb.push_back(0x01);              // doBind = true
    tp::appendU16(cb, kListenPort);  // localPort
    tp::appendIpv4Addr(cb, 0);       // localAddr = any
    const auto cb_resp = stimulus::testabilityCall(cfg, tp::kGidTcp, tp::kPidCreateAndBind, cb);
    ASSERT_TRUE(cb_resp.eok());
    ASSERT_EQ(cb_resp.dat.size(), 2u);
    const std::uint16_t listen_sid =
        static_cast<std::uint16_t>((cb_resp.dat[0] << 8) | cb_resp.dat[1]);

    int cfd = -1;
    const auto ev = stimulus::testabilityTcpListenAndAccept(
        cfg, listen_sid, /*max_con=*/1,
        [&] {
            cfd = ::socket(AF_INET, SOCK_STREAM, 0);
            if (cfd >= 0) {
                sockaddr_in da{};
                da.sin_family = AF_INET;
                da.sin_port = htons(kListenPort);
                da.sin_addr.s_addr = ::htonl(INADDR_LOOPBACK);
                if (::connect(cfd, reinterpret_cast<sockaddr *>(&da), sizeof(da)) < 0) {
                    ::close(cfd);
                    cfd = -1;
                }
            }
        },
        /*resp_timeout_ms=*/1000, /*event_timeout_ms=*/2000);

    ASSERT_TRUE(ev.received) << "DUT did not emit the accept Event";
    EXPECT_EQ(ev.listen_socket_id, listen_sid);
    EXPECT_NE(ev.new_socket_id, 0u);
    EXPECT_NE(ev.new_socket_id, listen_sid);
    EXPECT_EQ(ev.client_addr_be, ::htonl(INADDR_LOOPBACK));
    EXPECT_NE(ev.client_port, 0u);

    if (cfd >= 0) {
        ::close(cfd);
    }
    EXPECT_TRUE(stimulus::testabilityCloseSocket(cfg, tp::kGidTcp, ev.new_socket_id).eok());
    EXPECT_TRUE(stimulus::testabilityCloseSocket(cfg, tp::kGidTcp, listen_sid).eok());
}

// END_TEST must terminate a pending accept thread (no connection ever arrives)
// and leave the server responsive — a leaked thread would hang TearDown's join.
TEST_F(TestabilityServerTest, EndTestTerminatesPendingAcceptThread) {
    const auto cfg = loopbackConfig();
    constexpr std::uint16_t kListenPort = 39812;

    std::vector<std::uint8_t> cb;
    cb.push_back(0x01);
    tp::appendU16(cb, kListenPort);
    tp::appendIpv4Addr(cb, 0);
    const auto cb_resp = stimulus::testabilityCall(cfg, tp::kGidTcp, tp::kPidCreateAndBind, cb);
    ASSERT_TRUE(cb_resp.eok());
    const std::uint16_t listen_sid =
        static_cast<std::uint16_t>((cb_resp.dat[0] << 8) | cb_resp.dat[1]);

    // Issue LISTEN_AND_ACCEPT directly (E_OK returns immediately); never connect.
    std::vector<std::uint8_t> la;
    tp::appendU16(la, listen_sid);
    tp::appendU16(la, 1);  // maxCon
    EXPECT_TRUE(
        stimulus::testabilityCall(cfg, tp::kGidTcp, tp::kPidListenAndAccept, la).eok());

    // END_TEST terminates the pending accept thread, then the server still answers.
    EXPECT_TRUE(stimulus::testabilityEndTest(cfg, /*tc_id=*/0, "reset").eok());
    EXPECT_TRUE(stimulus::testabilityStartTest(cfg).eok());
}

// ── Tier 2 seam: TestabilityControl::socketControl() over the real server ──

// The socket-control seam reports kCapSocketData and drives UDP open/close +
// TCP active open + send, all through the backend-agnostic ISocketControl.
TEST_F(TestabilityServerTest, SocketControlSeamActiveOpenAndSend) {
    sce::TestabilityControl ctrl(loopbackConfig());
    EXPECT_EQ(ctrl.capabilities() & sce::kCapSocketData, sce::kCapSocketData);
    sce::ISocketControl *sc = ctrl.socketControl();
    ASSERT_NE(sc, nullptr);

    // UDP: open (bound) then close.
    const auto udp = sc->openUdp(sce::BindSpec{/*do_bind=*/true, 0xFFFF, 0});
    ASSERT_TRUE(udp.has_value());
    EXPECT_TRUE(sc->closeSocket(*udp));

    // TCP active open: tester listener accepts the DUT's connect; send is read back.
    const int lfd = ::socket(AF_INET, SOCK_STREAM, 0);
    ASSERT_GE(lfd, 0);
    int on = 1;
    ::setsockopt(lfd, SOL_SOCKET, SO_REUSEADDR, &on, sizeof(on));
    sockaddr_in la{};
    la.sin_family = AF_INET;
    la.sin_addr.s_addr = ::htonl(INADDR_LOOPBACK);
    la.sin_port = 0;
    ASSERT_EQ(::bind(lfd, reinterpret_cast<sockaddr *>(&la), sizeof(la)), 0);
    ASSERT_EQ(::listen(lfd, 1), 0);
    socklen_t ll = sizeof(la);
    ASSERT_EQ(::getsockname(lfd, reinterpret_cast<sockaddr *>(&la), &ll), 0);
    timeval tv{};
    tv.tv_sec = 2;
    ::setsockopt(lfd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));

    const auto conn = sc->connectTcp(sce::Endpoint{::htonl(INADDR_LOOPBACK), ntohs(la.sin_port)});
    ASSERT_TRUE(conn.has_value());
    sockaddr_in peer{};
    socklen_t pl = sizeof(peer);
    const int afd = ::accept(lfd, reinterpret_cast<sockaddr *>(&peer), &pl);
    ASSERT_GE(afd, 0);

    const std::vector<std::uint8_t> body = {'T', 'C', '8'};
    EXPECT_TRUE(sc->sendTcp(*conn, body, /*total_len=*/3));
    ::setsockopt(afd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
    std::uint8_t buf[16];
    const ssize_t n = ::recv(afd, buf, sizeof(buf), 0);
    EXPECT_EQ(n, 3);

    EXPECT_TRUE(sc->closeSocket(conn->socket));
    ::close(afd);
    ::close(lfd);
}

// Passive open through the seam: acceptTcp binds+listens on the DUT, the
// trigger connects in, and the accepted connection carries the client endpoint.
TEST_F(TestabilityServerTest, SocketControlSeamPassiveOpen) {
    sce::TestabilityControl ctrl(loopbackConfig());
    sce::ISocketControl *sc = ctrl.socketControl();
    ASSERT_NE(sc, nullptr);

    constexpr std::uint16_t kListenPort = 39813;
    int cfd = -1;
    const auto conn = sc->acceptTcp(
        sce::BindSpec{/*do_bind=*/true, kListenPort, 0},
        [&] {
            cfd = ::socket(AF_INET, SOCK_STREAM, 0);
            if (cfd >= 0) {
                sockaddr_in da{};
                da.sin_family = AF_INET;
                da.sin_port = htons(kListenPort);
                da.sin_addr.s_addr = ::htonl(INADDR_LOOPBACK);
                if (::connect(cfd, reinterpret_cast<sockaddr *>(&da), sizeof(da)) < 0) {
                    ::close(cfd);
                    cfd = -1;
                }
            }
        });

    ASSERT_TRUE(conn.has_value());
    EXPECT_NE(conn->socket.id, 0u);
    EXPECT_EQ(conn->peer.addr_be, ::htonl(INADDR_LOOPBACK));
    EXPECT_NE(conn->peer.port, 0u);
    if (cfd >= 0) {
        ::close(cfd);
    }
    EXPECT_TRUE(sc->closeSocket(conn->socket));
}

// CONNECT / SEND_DATA / CLOSE_SOCKET against an unknown socketId -> E_ISD.
TEST_F(TestabilityServerTest, UnknownSocketIdIsInvalid) {
    const auto cfg = loopbackConfig();
    const std::uint16_t bogus = 0xBEEF;
    EXPECT_EQ(stimulus::testabilityTcpConnect(cfg, bogus, 80, ::htonl(INADDR_LOOPBACK)).rid,
              tp::kRidEIsd);
    EXPECT_EQ(stimulus::testabilityTcpSendData(cfg, bogus, 1, 0, {0x01}).rid, tp::kRidEIsd);
    EXPECT_EQ(stimulus::testabilityCloseSocket(cfg, tp::kGidTcp, bogus).rid, tp::kRidEIsd);
}

}  // namespace
}  // namespace tc8
