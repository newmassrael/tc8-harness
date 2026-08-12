#include <arpa/inet.h>
#include <linux/if_link.h>
#include <linux/netlink.h>
#include <linux/rtnetlink.h>
#include <net/if.h>
#include <netinet/in.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <unistd.h>

#include <cerrno>
#include <chrono>
#include <cstdint>
#include <cstring>
#include <fstream>
#include <memory>
#include <stdexcept>
#include <thread>
#include <vector>

#include <gtest/gtest.h>

#include "netns_test_util.h"
#include "test_port_util.h"
#include "tc8/linux_socket_backend.h"
#include "sce_integration/dut_control.h"
#include "tc8/testability_client.h"
#include "tc8/testability_protocol.h"
#include "tc8/testability/middleware.h"
#include "tc8/testability/protocol_server.h"

// Server-side integration: drive the real DUT-side TestabilityServer (which is
// vsomeip-independent — a hand-rolled SOME/IP endpoint over a plain socket)
// with the real tester-side client wrappers over loopback. This exercises the
// GENERAL lifecycle, the UDP CREATE_AND_BIND/CLOSE_SOCKET path (guarding the
// socktype refactor), and the full TCP active-open lifecycle
// (CREATE_AND_BIND + CONNECT + SEND_DATA + CLOSE_SOCKET) end to end.

namespace tc8 {
namespace {

namespace tp = ::tc8::testability;
using namespace testutil;  // createDummyIface / deleteIface / hasNetAdmin / ScopeExit

// An uncommon port below the ephemeral range (see test_port_util.h for why every
// fixed test port must be), distinct from the canonical 30700 so a tc8-dut a
// developer has running does not collide with the hermetic server bind.
constexpr std::uint16_t kTestPort = 31701;
TC8_STATIC_ASSERT_TEST_PORT(kTestPort);

testability::TestabilityConfig loopbackConfig() {
    testability::TestabilityConfig cfg;
    cfg.dut_ip_be = ::htonl(INADDR_LOOPBACK);
    cfg.dut_port = kTestPort;
    return cfg;
}

class TestabilityServerTest : public ::testing::Test {
protected:
    void SetUp() override { ASSERT_TRUE(server_.start(kTestPort)); }
    void TearDown() override { server_.stop(); }

    testability::ProtocolServer server_{std::make_unique<dut::LinuxSocketBackend>()};
};

TEST_F(TestabilityServerTest, GeneralLifecycleRoundTrips) {
    const auto cfg = loopbackConfig();
    const auto v = testability::testabilityGetVersion(cfg);
    ASSERT_TRUE(v.has_value());
    EXPECT_EQ(v->major, tp::kVersionMajor);
    EXPECT_EQ(v->minor, tp::kVersionMinor);
    EXPECT_EQ(v->patch, tp::kVersionPatch);

    EXPECT_TRUE(testability::testabilityStartTest(cfg).eok());
    EXPECT_TRUE(testability::testabilityEndTest(cfg, /*tc_id=*/1, "server-test").eok());
}

// The socktype refactor must keep the UDP CREATE_AND_BIND/CLOSE_SOCKET path
// working (a SOCK_DGRAM socket created, then closed).
TEST_F(TestabilityServerTest, UdpCreateAndCloseStillWork) {
    const auto cfg = loopbackConfig();
    std::vector<std::uint8_t> cb;
    cb.push_back(0x01);              // doBind = true
    tp::appendU16(cb, 0xFFFF);       // localPort = PORT_ANY
    tp::appendIpv4Addr(cb, 0);       // localAddr = any
    const auto cb_resp = testability::testabilityCall(cfg, tp::kGidUdp, tp::kPidCreateAndBind, cb);
    ASSERT_TRUE(cb_resp.eok());
    ASSERT_EQ(cb_resp.dat.size(), 2u);
    const std::uint16_t sid =
        static_cast<std::uint16_t>((cb_resp.dat[0] << 8) | cb_resp.dat[1]);
    EXPECT_TRUE(testability::testabilityCloseSocket(cfg, tp::kGidUdp, sid).eok());
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
    const auto sock = testability::testabilityCreateAndBind(cfg, tp::kGidTcp, /*do_bind=*/false,
                                                         /*local_port=*/0xFFFF,
                                                         /*local_addr_be=*/0);
    ASSERT_TRUE(sock.has_value());
    const auto co = testability::testabilityTcpConnect(cfg, *sock, listen_port,
                                                    ::htonl(INADDR_LOOPBACK));
    EXPECT_TRUE(co.eok());

    sockaddr_in peer{};
    socklen_t pl = sizeof(peer);
    const int afd = ::accept(lfd, reinterpret_cast<sockaddr *>(&peer), &pl);
    EXPECT_GE(afd, 0) << "DUT CONNECT did not reach ESTABLISHED (accept timed out)";

    // SEND_DATA (TCP): bytes flow over the established connection.
    const std::vector<std::uint8_t> body = {'T', 'C', '8'};
    const auto sd = testability::testabilityTcpSendData(cfg, *sock, /*total_len=*/3,
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

    EXPECT_TRUE(testability::testabilityCloseSocket(cfg, tp::kGidTcp, *sock).eok());
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

    const auto sock = testability::testabilityCreateAndBind(cfg, tp::kGidTcp, false, 0xFFFF, 0);
    ASSERT_TRUE(sock.has_value());
    ASSERT_TRUE(testability::testabilityTcpConnect(cfg, *sock, listen_port,
                                                ::htonl(INADDR_LOOPBACK))
                    .eok());
    sockaddr_in peer{};
    socklen_t pl = sizeof(peer);
    const int afd = ::accept(lfd, reinterpret_cast<sockaddr *>(&peer), &pl);
    ASSERT_GE(afd, 0);

    // data = {AB}, totalLen = 4 -> four AB bytes on the wire.
    const std::vector<std::uint8_t> body = {0xAB};
    ASSERT_TRUE(testability::testabilityTcpSendData(cfg, *sock, /*total_len=*/4, 0, body).eok());

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
    EXPECT_TRUE(testability::testabilityCloseSocket(cfg, tp::kGidTcp, *sock).eok());
}

// CONNECT to a port with no listener must fail (bounded, not hang) and not
// stall later requests on the single server thread.
TEST_F(TestabilityServerTest, TcpConnectToDeadPortReturnsError) {
    const auto cfg = loopbackConfig();
    const auto sock = testability::testabilityCreateAndBind(cfg, tp::kGidTcp, false, 0xFFFF, 0);
    ASSERT_TRUE(sock.has_value());
    // Port 1 on loopback: nothing listening -> connection refused.
    const auto co = testability::testabilityTcpConnect(cfg, *sock, /*dest_port=*/1,
                                                    ::htonl(INADDR_LOOPBACK),
                                                    /*timeout_ms=*/1500);
    EXPECT_TRUE(co.ok);              // the SP itself round-tripped
    EXPECT_NE(co.rid, tp::kRidEOk);  // but reported a non-success result

    // The server thread is still responsive afterwards.
    EXPECT_TRUE(testability::testabilityCloseSocket(cfg, tp::kGidTcp, *sock).eok());
    EXPECT_TRUE(testability::testabilityStartTest(cfg).eok());
}

// Full passive-open loop: bind a DUT listen socket, LISTEN_AND_ACCEPT, connect
// to it from the tester, and confirm the DUT emits the accept Event with the
// new socket id and the tester's port/address.
TEST_F(TestabilityServerTest, TcpListenAndAcceptEmitsEventOnConnect) {
    const auto cfg = loopbackConfig();
    constexpr std::uint16_t kListenPort = 31811;
    TC8_STATIC_ASSERT_TEST_PORT(kListenPort);

    // CREATE_AND_BIND (TCP) with a bound, known listen port.
    std::vector<std::uint8_t> cb;
    cb.push_back(0x01);              // doBind = true
    tp::appendU16(cb, kListenPort);  // localPort
    tp::appendIpv4Addr(cb, 0);       // localAddr = any
    const auto cb_resp = testability::testabilityCall(cfg, tp::kGidTcp, tp::kPidCreateAndBind, cb);
    ASSERT_TRUE(cb_resp.eok());
    ASSERT_EQ(cb_resp.dat.size(), 2u);
    const std::uint16_t listen_sid =
        static_cast<std::uint16_t>((cb_resp.dat[0] << 8) | cb_resp.dat[1]);

    int cfd = -1;
    const auto ev = testability::testabilityTcpListenAndAccept(
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
    EXPECT_TRUE(testability::testabilityCloseSocket(cfg, tp::kGidTcp, ev.new_socket_id).eok());
    EXPECT_TRUE(testability::testabilityCloseSocket(cfg, tp::kGidTcp, listen_sid).eok());
}

// END_TEST must terminate a pending accept thread (no connection ever arrives)
// and leave the server responsive — a leaked thread would hang TearDown's join.
TEST_F(TestabilityServerTest, EndTestTerminatesPendingAcceptThread) {
    const auto cfg = loopbackConfig();
    constexpr std::uint16_t kListenPort = 31812;
    TC8_STATIC_ASSERT_TEST_PORT(kListenPort);

    std::vector<std::uint8_t> cb;
    cb.push_back(0x01);
    tp::appendU16(cb, kListenPort);
    tp::appendIpv4Addr(cb, 0);
    const auto cb_resp = testability::testabilityCall(cfg, tp::kGidTcp, tp::kPidCreateAndBind, cb);
    ASSERT_TRUE(cb_resp.eok());
    const std::uint16_t listen_sid =
        static_cast<std::uint16_t>((cb_resp.dat[0] << 8) | cb_resp.dat[1]);

    // Issue LISTEN_AND_ACCEPT directly (E_OK returns immediately); never connect.
    std::vector<std::uint8_t> la;
    tp::appendU16(la, listen_sid);
    tp::appendU16(la, 1);  // maxCon
    EXPECT_TRUE(
        testability::testabilityCall(cfg, tp::kGidTcp, tp::kPidListenAndAccept, la).eok());

    // END_TEST terminates the pending accept thread, then the server still answers.
    EXPECT_TRUE(testability::testabilityEndTest(cfg, /*tc_id=*/0, "reset").eok());
    EXPECT_TRUE(testability::testabilityStartTest(cfg).eok());
}

// RECEIVE_AND_FORWARD (TCP): bytes queued before the arm are consumed and
// counted as dropCnt; bytes sent after the arm are forwarded back as an Event.
TEST_F(TestabilityServerTest, TcpReceiveAndForwardConsumesThenForwards) {
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

    const auto sock = testability::testabilityCreateAndBind(cfg, tp::kGidTcp, false, 0xFFFF, 0);
    ASSERT_TRUE(sock.has_value());
    ASSERT_TRUE(testability::testabilityTcpConnect(cfg, *sock, ntohs(la.sin_port),
                                                ::htonl(INADDR_LOOPBACK))
                    .eok());
    const int afd = ::accept(lfd, nullptr, nullptr);
    ASSERT_GE(afd, 0);

    // Three bytes arrive BEFORE the arm — they must be drained and counted as
    // dropCnt (not forwarded). Give the DUT kernel a moment to queue them.
    const std::vector<std::uint8_t> pre = {'X', 'Y', 'Z'};
    ASSERT_EQ(::send(afd, pre.data(), pre.size(), 0), 3);
    std::this_thread::sleep_for(std::chrono::milliseconds(100));

    // Arm; in on_armed, send the payload to be forwarded back as one Event.
    const std::vector<std::uint8_t> body = {'T', 'C', '8', 'd', 'a', 't', 'a'};
    const auto res = testability::testabilityReceiveAndForward(
        cfg, *sock, /*max_fwd=*/16, /*max_len=*/static_cast<std::uint16_t>(body.size()),
        [&] { ::send(afd, body.data(), body.size(), 0); });

    EXPECT_TRUE(res.ok);
    EXPECT_EQ(res.drop_cnt, pre.size());
    EXPECT_EQ(res.full_len, body.size());
    EXPECT_EQ(res.payload, body);

    ::close(afd);
    ::close(lfd);
    EXPECT_TRUE(testability::testabilityCloseSocket(cfg, tp::kGidTcp, *sock).eok());
}

// RECEIVE_AND_FORWARD aggregation: a stream the DUT reads as several recv()s
// (each forwarded as its own Event) is reassembled by the client into one
// max_len buffer — the seam receiveTcp's multi-segment reassembly contract
// (TCP_CALL_RECEIVE_04), matching the opcode OpReceiveTcpData recv-loop.
TEST_F(TestabilityServerTest, TcpReceiveAndForwardReassemblesMultiSegment) {
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

    const auto sock = testability::testabilityCreateAndBind(cfg, tp::kGidTcp, false, 0xFFFF, 0);
    ASSERT_TRUE(sock.has_value());
    ASSERT_TRUE(testability::testabilityTcpConnect(cfg, *sock, ntohs(la.sin_port),
                                                ::htonl(INADDR_LOOPBACK))
                    .eok());
    const int afd = ::accept(lfd, nullptr, nullptr);
    ASSERT_GE(afd, 0);

    // Four 32-byte segments with 20 ms gaps so the DUT's receiveLoop reads them
    // as separate recv()s (separate forward Events). The client must concatenate
    // them back into the 128-byte buffer regardless of how the stream chunked.
    constexpr int kSeg = 32;
    constexpr int kCount = 4;
    std::vector<std::uint8_t> expected;
    const auto res = testability::testabilityReceiveAndForward(
        cfg, *sock, /*max_fwd=*/kSeg * kCount, /*max_len=*/kSeg * kCount, [&] {
            for (int i = 0; i < kCount; ++i) {
                const std::vector<std::uint8_t> chunk(kSeg, static_cast<std::uint8_t>(0xA0 + i));
                ::send(afd, chunk.data(), chunk.size(), 0);
                expected.insert(expected.end(), chunk.begin(), chunk.end());
                std::this_thread::sleep_for(std::chrono::milliseconds(20));
            }
        });

    EXPECT_TRUE(res.ok);
    EXPECT_EQ(res.payload.size(), static_cast<std::size_t>(kSeg * kCount));
    EXPECT_EQ(res.payload, expected);

    ::close(afd);
    ::close(lfd);
    EXPECT_TRUE(testability::testabilityCloseSocket(cfg, tp::kGidTcp, *sock).eok());
}

// UDP RECEIVE_AND_FORWARD (PRS_TPSP §6.10): a datagram received before the arm
// counts as dropCnt, and each datagram received in the active phase is forwarded
// as an Event carrying fullLen + the datagram's srcPort/srcAddr + payload — the
// connectionless shape (distinct from TCP's fullLen+payload). Hand-rolled because
// the async forward Event is addressed to the requester socket, so a single
// persistent test-system socket issues the requests and reads the Event.
TEST_F(TestabilityServerTest, UdpReceiveAndForwardEmitsDatagramSourceEvent) {
    const int ts = ::socket(AF_INET, SOCK_DGRAM, 0);
    ASSERT_GE(ts, 0);
    sockaddr_in tsa{};
    tsa.sin_family = AF_INET;
    tsa.sin_addr.s_addr = ::htonl(INADDR_LOOPBACK);
    tsa.sin_port = 0;
    ASSERT_EQ(::bind(ts, reinterpret_cast<sockaddr *>(&tsa), sizeof(tsa)), 0);
    timeval tv{};
    tv.tv_sec = 2;
    ::setsockopt(ts, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));

    sockaddr_in dut{};
    dut.sin_family = AF_INET;
    dut.sin_addr.s_addr = ::htonl(INADDR_LOOPBACK);
    dut.sin_port = htons(kTestPort);

    // Send a testability request from `ts` to the DUT, return the response DAT.
    const auto call = [&](std::uint8_t gid, std::uint8_t pid,
                          const std::vector<std::uint8_t> &dat) -> std::vector<std::uint8_t> {
        tp::Header h;
        h.method_id = tp::methodId(gid, pid);
        const auto msg = tp::buildMessage(h, dat.data(), dat.size());
        EXPECT_GT(::sendto(ts, msg.data(), msg.size(), 0, reinterpret_cast<sockaddr *>(&dut),
                           sizeof(dut)),
                  0);
        std::uint8_t rb[1500];
        const ssize_t rn = ::recvfrom(ts, rb, sizeof(rb), 0, nullptr, nullptr);
        if (rn < static_cast<ssize_t>(tp::kHeaderSize)) {
            return {};
        }
        return std::vector<std::uint8_t>(rb + tp::kHeaderSize, rb + rn);
    };

    // CREATE_AND_BIND a UDP socket on a known DUT port so the sender can target it.
    constexpr std::uint16_t kDutUdpPort = 31733;
    TC8_STATIC_ASSERT_TEST_PORT(kDutUdpPort);
    std::vector<std::uint8_t> cb;
    cb.push_back(0x01);             // doBind = true
    tp::appendU16(cb, kDutUdpPort);  // localPort
    tp::appendIpv4Addr(cb, 0);       // localAddr = any
    const auto cb_resp = call(tp::kGidUdp, tp::kPidCreateAndBind, cb);
    ASSERT_EQ(cb_resp.size(), 2u);
    const std::uint16_t sid = tp::readU16(cb_resp.data());

    // A separate sender → the DUT's bound port.
    const int snd = ::socket(AF_INET, SOCK_DGRAM, 0);
    ASSERT_GE(snd, 0);
    sockaddr_in sa{};
    sa.sin_family = AF_INET;
    sa.sin_addr.s_addr = ::htonl(INADDR_LOOPBACK);
    sa.sin_port = 0;
    ASSERT_EQ(::bind(snd, reinterpret_cast<sockaddr *>(&sa), sizeof(sa)), 0);
    socklen_t sl = sizeof(sa);
    ASSERT_EQ(::getsockname(snd, reinterpret_cast<sockaddr *>(&sa), &sl), 0);
    const std::uint16_t snd_port = ntohs(sa.sin_port);

    sockaddr_in to{};
    to.sin_family = AF_INET;
    to.sin_addr.s_addr = ::htonl(INADDR_LOOPBACK);
    to.sin_port = htons(kDutUdpPort);

    // One datagram BEFORE the arm (inactive phase) -> dropCnt.
    const std::vector<std::uint8_t> pre = {'P', 'R', 'E'};
    ASSERT_EQ(::sendto(snd, pre.data(), pre.size(), 0, reinterpret_cast<sockaddr *>(&to),
                       sizeof(to)),
              3);
    std::this_thread::sleep_for(std::chrono::milliseconds(100));

    // RECEIVE_AND_FORWARD(sid, maxFwd=16, maxLen=limitless) -> dropCnt == 3.
    std::vector<std::uint8_t> raf;
    tp::appendU16(raf, sid);
    tp::appendU16(raf, 16);      // maxFwd
    tp::appendU16(raf, 0xFFFF);  // maxLen (limitless)
    const auto raf_resp = call(tp::kGidUdp, tp::kPidReceiveAndForward, raf);
    ASSERT_EQ(raf_resp.size(), 2u);
    EXPECT_EQ(tp::readU16(raf_resp.data()), 3u) << "pre-arm datagram not counted as dropCnt";

    // Active phase: send a datagram; the DUT forwards it as an Event to `ts`.
    const std::vector<std::uint8_t> body = {'T', 'e', 's', 't', '1', '2', '3'};
    ASSERT_EQ(::sendto(snd, body.data(), body.size(), 0, reinterpret_cast<sockaddr *>(&to),
                       sizeof(to)),
              static_cast<ssize_t>(body.size()));

    std::uint8_t eb[1500];
    const ssize_t en = ::recvfrom(ts, eb, sizeof(eb), 0, nullptr, nullptr);
    ASSERT_GE(en, static_cast<ssize_t>(tp::kHeaderSize)) << "no forward Event arrived";
    const auto eh = tp::parseHeader(eb, static_cast<std::size_t>(en));
    ASSERT_TRUE(eh.has_value());
    EXPECT_TRUE(tp::isEvent(eh->method_id));
    EXPECT_EQ(tp::gidOf(eh->method_id), tp::kGidUdp);
    EXPECT_EQ(tp::pidOf(eh->method_id), tp::kPidReceiveAndForward);
    EXPECT_EQ(eh->tid, tp::kTidEvent);

    // Event DAT: fullLen(u16) + srcPort(u16) + srcAddr(ipxaddr) + payload(vint8).
    const std::uint8_t *ed = eb + tp::kHeaderSize;
    const std::size_t edl = static_cast<std::size_t>(en) - tp::kHeaderSize;
    ASSERT_GE(edl, 6u);
    EXPECT_EQ(tp::readU16(ed), static_cast<std::uint16_t>(body.size()));  // fullLen
    EXPECT_EQ(tp::readU16(ed + 2), snd_port);                            // srcPort
    std::size_t off = 4;
    const std::uint8_t *addr = nullptr;
    std::uint16_t addr_len = 0;
    ASSERT_TRUE(tp::readVint8(ed, edl, off, addr, addr_len));
    ASSERT_EQ(addr_len, 4u);
    std::uint32_t src_be = 0;
    std::memcpy(&src_be, addr, 4);
    EXPECT_EQ(src_be, ::htonl(INADDR_LOOPBACK));  // srcAddr
    const std::uint8_t *pl = nullptr;
    std::uint16_t pl_len = 0;
    ASSERT_TRUE(tp::readVint8(ed, edl, off, pl, pl_len));
    ASSERT_EQ(pl_len, static_cast<std::uint16_t>(body.size()));
    EXPECT_EQ(std::vector<std::uint8_t>(pl, pl + pl_len), body);  // payload

    std::vector<std::uint8_t> cs;
    tp::appendU16(cs, sid);
    call(tp::kGidUdp, tp::kPidCloseSocket, cs);  // joins the forward worker
    ::close(snd);
    ::close(ts);
}

// ── Tier 2 seam: ITcpControl / IUdpControl over the real testability server ──

// TCP control: capability bit set, active open against a tester listener (read
// back the DUT's send), driven through the backend-agnostic ITcpControl.
TEST_F(TestabilityServerTest, TcpControlSeamActiveOpenAndSend) {
    sce::TestabilityControl ctrl(loopbackConfig());
    EXPECT_EQ(ctrl.capabilities() & sce::kCapTcpControl, sce::kCapTcpControl);
    sce::ITcpControl *tcp = ctrl.tcpControl();
    ASSERT_NE(tcp, nullptr);

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

    const auto conn = tcp->connectTcp(sce::Endpoint{::htonl(INADDR_LOOPBACK), ntohs(la.sin_port)});
    ASSERT_TRUE(conn.has_value());
    sockaddr_in peer{};
    socklen_t pl = sizeof(peer);
    const int afd = ::accept(lfd, reinterpret_cast<sockaddr *>(&peer), &pl);
    ASSERT_GE(afd, 0);

    const std::vector<std::uint8_t> body = {'T', 'C', '8'};
    EXPECT_TRUE(tcp->sendTcp(conn->socket, body));
    ::setsockopt(afd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
    std::uint8_t buf[16];
    const ssize_t n = ::recv(afd, buf, sizeof(buf), 0);
    EXPECT_EQ(n, 3);

    EXPECT_TRUE(tcp->closeTcp(conn->socket));
    ::close(afd);
    ::close(lfd);
}

// TCP control half-close: shutdownTcpWr makes the DUT shutdown(SHUT_WR), so the
// kernel emits FIN and the tester's accepted socket reads EOF (recv == 0). The
// DUT fd lives on (read side open), so a subsequent closeTcp still succeeds —
// the "CLOSE then RECEIVE" lifecycle §4.8.6.8 TCP_CLOSING_07/_08 depend on.
TEST_F(TestabilityServerTest, TcpControlSeamShutdownWrEmitsFin) {
    sce::TestabilityControl ctrl(loopbackConfig());
    sce::ITcpControl *tcp = ctrl.tcpControl();
    ASSERT_NE(tcp, nullptr);

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

    const auto conn = tcp->connectTcp(sce::Endpoint{::htonl(INADDR_LOOPBACK), ntohs(la.sin_port)});
    ASSERT_TRUE(conn.has_value());
    const int afd = ::accept(lfd, nullptr, nullptr);
    ASSERT_GE(afd, 0);
    ::setsockopt(afd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));

    EXPECT_TRUE(tcp->shutdownTcpWr(conn->socket));
    std::uint8_t buf[16];
    const ssize_t n = ::recv(afd, buf, sizeof(buf), 0);
    EXPECT_EQ(n, 0) << "DUT did not FIN on shutdownTcpWr (tester saw no EOF)";

    EXPECT_TRUE(tcp->closeTcp(conn->socket));
    ::close(afd);
    ::close(lfd);
}

// TCP control abort: abortTcp makes the DUT close with SO_LINGER {1,0}, so the
// kernel emits a RST and the tester's accepted socket reads ECONNRESET — the
// abortive counterpart of closeTcp's graceful FIN (RFC 793 §3.9 ABORT). Backs
// the seam abortTcp used by TCP_CALL_ABORT_02/03.
TEST_F(TestabilityServerTest, TcpControlSeamAbortEmitsRst) {
    sce::TestabilityControl ctrl(loopbackConfig());
    sce::ITcpControl *tcp = ctrl.tcpControl();
    ASSERT_NE(tcp, nullptr);

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

    const auto conn = tcp->connectTcp(sce::Endpoint{::htonl(INADDR_LOOPBACK), ntohs(la.sin_port)});
    ASSERT_TRUE(conn.has_value());
    const int afd = ::accept(lfd, nullptr, nullptr);
    ASSERT_GE(afd, 0);
    timeval tv{};
    tv.tv_sec = 2;
    ::setsockopt(afd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));

    EXPECT_TRUE(tcp->abortTcp(conn->socket));
    // A graceful FIN would surface as recv == 0 (EOF); the RST surfaces as
    // recv == -1 / ECONNRESET.
    std::uint8_t buf[16];
    const ssize_t n = ::recv(afd, buf, sizeof(buf), 0);
    EXPECT_LT(n, 0) << "expected RST (ECONNRESET), got EOF/data n=" << n;
    EXPECT_EQ(errno, ECONNRESET);

    ::close(afd);
    ::close(lfd);
}

// TCP control receive: receiveTcp arms RECEIVE_AND_FORWARD, the trigger sends
// inbound bytes, and the forwarded payload comes back through the seam.
TEST_F(TestabilityServerTest, TcpControlSeamReceiveForwardsInbound) {
    sce::TestabilityControl ctrl(loopbackConfig());
    sce::ITcpControl *tcp = ctrl.tcpControl();
    ASSERT_NE(tcp, nullptr);

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

    const auto conn =
        tcp->connectTcp(sce::Endpoint{::htonl(INADDR_LOOPBACK), ntohs(la.sin_port)});
    ASSERT_TRUE(conn.has_value());
    const int afd = ::accept(lfd, nullptr, nullptr);
    ASSERT_GE(afd, 0);

    const std::vector<std::uint8_t> body = {'R', 'X', 'd', 'a', 't', 'a'};
    const auto got = tcp->receiveTcp(conn->socket, static_cast<std::uint16_t>(body.size()),
                                     [&] { ::send(afd, body.data(), body.size(), 0); });
    ASSERT_TRUE(got.has_value());
    EXPECT_EQ(*got, body);

    EXPECT_TRUE(tcp->closeTcp(conn->socket));
    ::close(afd);
    ::close(lfd);
}

// TCP control active open with an explicit local bind: the DUT's connection
// must source the bound local port, so the tester observes that exact port on
// accept(). Guards the connectTcp(peer, BindSpec) path the §4.8 seam pilot
// (TCP_BASICS_06) relies on to satisfy its src_port-pinned guard.
TEST_F(TestabilityServerTest, TcpControlSeamActiveOpenWithLocalBind) {
    sce::TestabilityControl ctrl(loopbackConfig());
    sce::ITcpControl *tcp = ctrl.tcpControl();
    ASSERT_NE(tcp, nullptr);

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

    constexpr std::uint16_t kLocalBindPort = 31822;
    TC8_STATIC_ASSERT_TEST_PORT(kLocalBindPort);
    const auto conn = tcp->connectTcp(
        sce::Endpoint{::htonl(INADDR_LOOPBACK), ntohs(la.sin_port)},
        sce::BindSpec{/*do_bind=*/true, kLocalBindPort, /*local_addr_be=*/0});
    ASSERT_TRUE(conn.has_value());

    sockaddr_in peer{};
    socklen_t pl = sizeof(peer);
    const int afd = ::accept(lfd, reinterpret_cast<sockaddr *>(&peer), &pl);
    ASSERT_GE(afd, 0);
    EXPECT_EQ(ntohs(peer.sin_port), kLocalBindPort)
        << "DUT did not source the bound local port";

    EXPECT_TRUE(tcp->closeTcp(conn->socket));
    ::close(afd);
    ::close(lfd);
}

// TCP control passive open: acceptTcp binds+listens on the DUT, the trigger
// connects in, and the accepted connection carries the client endpoint.
TEST_F(TestabilityServerTest, TcpControlSeamPassiveOpen) {
    sce::TestabilityControl ctrl(loopbackConfig());
    sce::ITcpControl *tcp = ctrl.tcpControl();
    ASSERT_NE(tcp, nullptr);

    constexpr std::uint16_t kListenPort = 31813;
    TC8_STATIC_ASSERT_TEST_PORT(kListenPort);
    int cfd = -1;
    const auto conn = tcp->acceptTcp(
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
    EXPECT_TRUE(tcp->closeTcp(conn->socket));
}

// UDP control: capability bit set, one-shot sendDatagram emits an observable
// datagram to a tester receiver.
TEST_F(TestabilityServerTest, UdpControlSeamOneShotSend) {
    sce::TestabilityControl ctrl(loopbackConfig());
    EXPECT_EQ(ctrl.capabilities() & sce::kCapUdpControl, sce::kCapUdpControl);
    sce::IUdpControl *udp = ctrl.udpControl();
    ASSERT_NE(udp, nullptr);

    const int rfd = ::socket(AF_INET, SOCK_DGRAM, 0);
    ASSERT_GE(rfd, 0);
    sockaddr_in ra{};
    ra.sin_family = AF_INET;
    ra.sin_addr.s_addr = ::htonl(INADDR_LOOPBACK);
    ra.sin_port = 0;
    ASSERT_EQ(::bind(rfd, reinterpret_cast<sockaddr *>(&ra), sizeof(ra)), 0);
    socklen_t rl = sizeof(ra);
    ASSERT_EQ(::getsockname(rfd, reinterpret_cast<sockaddr *>(&ra), &rl), 0);
    timeval tv{};
    tv.tv_sec = 2;
    ::setsockopt(rfd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));

    const std::vector<std::uint8_t> body = {'U', 'D', 'P'};
    EXPECT_TRUE(udp->sendDatagram(/*src_port=*/0xFFFF,
                                  sce::Endpoint{::htonl(INADDR_LOOPBACK), ntohs(ra.sin_port)},
                                  body));
    std::uint8_t buf[16];
    const ssize_t n = ::recv(rfd, buf, sizeof(buf), 0);
    EXPECT_EQ(n, 3);
    ::close(rfd);
}

// CONFIGURE_SOCKET TTL (PRS_TPSP §6.10.10 paramId 0x0000) must set IP_TTL on the
// DUT socket, observable as the TTL of a datagram it subsequently emits — the
// tester receiver reads the delivered TTL via IP_RECVTTL / recvmsg. This proves
// the paramId -> setsockopt mapping end to end on the wire (not just E_OK).
TEST_F(TestabilityServerTest, ConfigureSocketTtlAppliesToEmittedDatagram) {
    const auto cfg = loopbackConfig();

    // Tester UDP receiver asking the kernel to report each datagram's TTL.
    const int rfd = ::socket(AF_INET, SOCK_DGRAM, 0);
    ASSERT_GE(rfd, 0);
    int on = 1;
    ASSERT_EQ(::setsockopt(rfd, IPPROTO_IP, IP_RECVTTL, &on, sizeof(on)), 0);
    sockaddr_in ra{};
    ra.sin_family = AF_INET;
    ra.sin_addr.s_addr = ::htonl(INADDR_LOOPBACK);
    ra.sin_port = 0;
    ASSERT_EQ(::bind(rfd, reinterpret_cast<sockaddr *>(&ra), sizeof(ra)), 0);
    socklen_t rl = sizeof(ra);
    ASSERT_EQ(::getsockname(rfd, reinterpret_cast<sockaddr *>(&ra), &rl), 0);
    timeval tv{};
    tv.tv_sec = 2;
    ::setsockopt(rfd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));

    // DUT: create a UDP socket, set its TTL = 7, emit a datagram to the receiver.
    const auto sock =
        testability::testabilityCreateAndBind(cfg, tp::kGidUdp, /*do_bind=*/true, 0xFFFF, 0);
    ASSERT_TRUE(sock.has_value());

    constexpr std::uint8_t kTtl = 7;
    std::vector<std::uint8_t> cs;
    tp::appendU16(cs, *sock);        // socketId
    tp::appendU16(cs, tp::kCfgTtl);  // paramId 0x0000
    const std::uint8_t ttl_val = kTtl;
    tp::appendVint8(cs, &ttl_val, 1);  // paramVal (1 byte)
    EXPECT_TRUE(testability::testabilityCall(cfg, tp::kGidUdp, tp::kPidConfigureSocket, cs).eok());

    std::vector<std::uint8_t> sd;
    tp::appendU16(sd, *sock);                          // socketId
    tp::appendU16(sd, 3);                              // totalLen
    tp::appendU16(sd, ntohs(ra.sin_port));             // destPort
    tp::appendIpv4Addr(sd, ::htonl(INADDR_LOOPBACK));  // destAddr
    const std::vector<std::uint8_t> body = {'T', 'T', 'L'};
    tp::appendVint8(sd, body.data(), body.size());  // data
    EXPECT_TRUE(testability::testabilityCall(cfg, tp::kGidUdp, tp::kPidSendData, sd).eok());

    // recvmsg reads the payload plus the ancillary TTL (IP_RECVTTL -> cmsg IP_TTL).
    std::uint8_t buf[16];
    iovec iov{};
    iov.iov_base = buf;
    iov.iov_len = sizeof(buf);
    std::uint8_t ctl[CMSG_SPACE(sizeof(int))];
    msghdr msg{};
    msg.msg_iov = &iov;
    msg.msg_iovlen = 1;
    msg.msg_control = ctl;
    msg.msg_controllen = sizeof(ctl);
    const ssize_t n = ::recvmsg(rfd, &msg, 0);
    ASSERT_EQ(n, 3) << "datagram from the configured socket did not arrive";

    int got_ttl = -1;
    for (cmsghdr *c = CMSG_FIRSTHDR(&msg); c != nullptr; c = CMSG_NXTHDR(&msg, c)) {
        if (c->cmsg_level == IPPROTO_IP && c->cmsg_type == IP_TTL) {
            int v = 0;
            std::memcpy(&v, CMSG_DATA(c), sizeof(v));
            got_ttl = v;
        }
    }
    EXPECT_EQ(got_ttl, static_cast<int>(kTtl))
        << "CONFIGURE_SOCKET TTL not reflected on the emitted datagram";

    EXPECT_TRUE(testability::testabilityCloseSocket(cfg, tp::kGidUdp, *sock).eok());
    ::close(rfd);
}

// CONFIGURE_SOCKET TOS (paramId 0x0002) and PRIORITY (0x0001) both map to the
// IPv4 TOS byte (IP_TOS): the value set on the DUT socket must appear as the TOS
// of a datagram it then emits, read by the tester via IP_RECVTOS / recvmsg. This
// is the second IP-header field — after the TTL above — that the hermetic
// loopback test can observe through a control message without a raw socket. The
// DF bit (IP_MTU_DISCOVER), UDP checksum elision (SO_NO_CHECK) and TCP MSS option
// (TCP_MAXSEG) would each need CAP_NET_RAW packet capture to read off the wire,
// so those parameters are pinned at the mapping/length contract level below.
TEST_F(TestabilityServerTest, ConfigureSocketTosAndPriorityApplyToEmittedDatagram) {
    const auto cfg = loopbackConfig();

    // Tester UDP receiver asking the kernel to report each datagram's TOS byte.
    const int rfd = ::socket(AF_INET, SOCK_DGRAM, 0);
    ASSERT_GE(rfd, 0);
    int on = 1;
    ASSERT_EQ(::setsockopt(rfd, IPPROTO_IP, IP_RECVTOS, &on, sizeof(on)), 0);
    sockaddr_in ra{};
    ra.sin_family = AF_INET;
    ra.sin_addr.s_addr = ::htonl(INADDR_LOOPBACK);
    ra.sin_port = 0;
    ASSERT_EQ(::bind(rfd, reinterpret_cast<sockaddr *>(&ra), sizeof(ra)), 0);
    socklen_t rl = sizeof(ra);
    ASSERT_EQ(::getsockname(rfd, reinterpret_cast<sockaddr *>(&ra), &rl), 0);
    timeval tv{};
    tv.tv_sec = 2;
    ::setsockopt(rfd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));

    const auto sock =
        testability::testabilityCreateAndBind(cfg, tp::kGidUdp, /*do_bind=*/true, 0xFFFF, 0);
    ASSERT_TRUE(sock.has_value());

    // Set <paramId>=<value> on the DUT socket, have it emit one datagram, and
    // return the TOS byte the receiver observed (-1 if nothing / no cmsg).
    const auto emitAndReadTos = [&](std::uint16_t param_id, std::uint8_t value) -> int {
        std::vector<std::uint8_t> cs;
        tp::appendU16(cs, *sock);     // socketId
        tp::appendU16(cs, param_id);  // paramId
        tp::appendVint8(cs, &value, 1);
        EXPECT_TRUE(
            testability::testabilityCall(cfg, tp::kGidUdp, tp::kPidConfigureSocket, cs).eok());

        std::vector<std::uint8_t> sd;
        tp::appendU16(sd, *sock);                          // socketId
        tp::appendU16(sd, 3);                              // totalLen
        tp::appendU16(sd, ntohs(ra.sin_port));             // destPort
        tp::appendIpv4Addr(sd, ::htonl(INADDR_LOOPBACK));  // destAddr
        const std::vector<std::uint8_t> body = {'T', 'O', 'S'};
        tp::appendVint8(sd, body.data(), body.size());
        EXPECT_TRUE(testability::testabilityCall(cfg, tp::kGidUdp, tp::kPidSendData, sd).eok());

        std::uint8_t buf[16];
        iovec iov{};
        iov.iov_base = buf;
        iov.iov_len = sizeof(buf);
        std::uint8_t ctl[CMSG_SPACE(sizeof(int))];
        msghdr msg{};
        msg.msg_iov = &iov;
        msg.msg_iovlen = 1;
        msg.msg_control = ctl;
        msg.msg_controllen = sizeof(ctl);
        const ssize_t n = ::recvmsg(rfd, &msg, 0);
        EXPECT_EQ(n, 3) << "datagram from the configured socket did not arrive";
        int tos = -1;
        for (cmsghdr *c = CMSG_FIRSTHDR(&msg); c != nullptr; c = CMSG_NXTHDR(&msg, c)) {
            // IP_RECVTOS delivers the TOS as a single byte (kernel ip_cmsg_recv_tos).
            if (c->cmsg_level == IPPROTO_IP && c->cmsg_type == IP_TOS) {
                std::uint8_t v = 0;
                std::memcpy(&v, CMSG_DATA(c), sizeof(v));
                tos = v;
            }
        }
        return tos;
    };

    // TOS selector (0x0002): a clean DSCP value with ECN bits clear so it
    // round-trips byte-for-byte on loopback.
    EXPECT_EQ(emitAndReadTos(tp::kCfgTos, 0x28), 0x28)
        << "CONFIGURE_SOCKET TOS not reflected on the emitted datagram";
    // PRIORITY selector (0x0001) drives the same IP_TOS byte — a distinct value
    // proves it is the parameter, not a stale setting, that reached the wire.
    EXPECT_EQ(emitAndReadTos(tp::kCfgPriority, 0x10), 0x10)
        << "CONFIGURE_SOCKET PRIORITY not reflected on the emitted datagram's TOS";

    EXPECT_TRUE(testability::testabilityCloseSocket(cfg, tp::kGidUdp, *sock).eok());
    ::close(rfd);
}

// CONFIGURE_SOCKET result codes: unknown socketId -> E_ISD, a truncated request
// -> E_INV, an unknown paramId -> E_NTF, and a valid parameter -> E_OK.
TEST_F(TestabilityServerTest, ConfigureSocketResultCodes) {
    const auto cfg = loopbackConfig();

    // Unknown socketId (well-formed message, no such socket).
    {
        std::vector<std::uint8_t> cs;
        tp::appendU16(cs, 0xBEEF);
        tp::appendU16(cs, tp::kCfgTtl);
        const std::uint8_t v = 5;
        tp::appendVint8(cs, &v, 1);
        EXPECT_EQ(testability::testabilityCall(cfg, tp::kGidUdp, tp::kPidConfigureSocket, cs).rid,
                  tp::kRidEIsd);
    }

    const auto sock = testability::testabilityCreateAndBind(cfg, tp::kGidTcp, false, 0xFFFF, 0);
    ASSERT_TRUE(sock.has_value());

    // Truncated: socketId only, no paramId / paramVal.
    {
        std::vector<std::uint8_t> cs;
        tp::appendU16(cs, *sock);
        EXPECT_EQ(testability::testabilityCall(cfg, tp::kGidTcp, tp::kPidConfigureSocket, cs).rid,
                  tp::kRidEInv);
    }

    // Unknown paramId on a valid socket.
    {
        std::vector<std::uint8_t> cs;
        tp::appendU16(cs, *sock);
        tp::appendU16(cs, 0x00FF);  // not a defined selector
        const std::uint8_t v = 1;
        tp::appendVint8(cs, &v, 1);
        EXPECT_EQ(testability::testabilityCall(cfg, tp::kGidTcp, tp::kPidConfigureSocket, cs).rid,
                  tp::kRidENtf);
    }

    // Valid: disable Nagle on the TCP socket (TCP_NODELAY).
    {
        std::vector<std::uint8_t> cs;
        tp::appendU16(cs, *sock);
        tp::appendU16(cs, tp::kCfgNagle);
        const std::uint8_t v = 0;  // disable Nagle
        tp::appendVint8(cs, &v, 1);
        EXPECT_TRUE(
            testability::testabilityCall(cfg, tp::kGidTcp, tp::kPidConfigureSocket, cs).eok());
    }

    EXPECT_TRUE(testability::testabilityCloseSocket(cfg, tp::kGidTcp, *sock).eok());
}

// CONFIGURE_SOCKET parameter-mapping contract for the selectors whose on-wire
// effect a hermetic loopback test cannot read without CAP_NET_RAW packet capture
// (the DF bit, TCP MSS option and UDP checksum elision). Each defined selector
// must reach the backend and return E_OK on a socket of the right family, and
// each fixed-width selector must reject a wrong-length paramVal with E_INV. This
// pins the paramId -> setsockopt mapping table — and its per-parameter length
// gate — even where the emitted header field is not observable here. (The TTL
// and TOS/PRIORITY selectors are additionally verified on the wire above.)
TEST_F(TestabilityServerTest, ConfigureSocketParameterMappingContract) {
    const auto cfg = loopbackConfig();

    const auto cfgCall = [&](std::uint8_t gid, std::uint16_t sock, std::uint16_t param_id,
                             const std::vector<std::uint8_t> &param_val) {
        std::vector<std::uint8_t> cs;
        tp::appendU16(cs, sock);
        tp::appendU16(cs, param_id);
        tp::appendVint8(cs, param_val.data(), param_val.size());
        return testability::testabilityCall(cfg, gid, tp::kPidConfigureSocket, cs).rid;
    };

    // UDP socket: DONT_FRAGMENT (IP_MTU_DISCOVER) and UDP_CHECKSUM (SO_NO_CHECK),
    // both single-byte selectors.
    {
        const auto sock =
            testability::testabilityCreateAndBind(cfg, tp::kGidUdp, /*do_bind=*/true, 0xFFFF, 0);
        ASSERT_TRUE(sock.has_value());
        EXPECT_EQ(cfgCall(tp::kGidUdp, *sock, tp::kCfgDontFragment, {0x01}), tp::kRidEOk);
        EXPECT_EQ(cfgCall(tp::kGidUdp, *sock, tp::kCfgDontFragment, {0x00}), tp::kRidEOk);
        EXPECT_EQ(cfgCall(tp::kGidUdp, *sock, tp::kCfgUdpChecksum, {0x01}), tp::kRidEOk);
        // Wrong-length paramVal (2 bytes where the fixed(1) gate wants 1) -> E_INV.
        EXPECT_EQ(cfgCall(tp::kGidUdp, *sock, tp::kCfgDontFragment, {0x00, 0x00}),
                  tp::kRidEInv);
        EXPECT_TRUE(testability::testabilityCloseSocket(cfg, tp::kGidUdp, *sock).eok());
    }

    // TCP socket: MSS (TCP_MAXSEG), a two-byte selector, plus its length gate.
    {
        const auto sock =
            testability::testabilityCreateAndBind(cfg, tp::kGidTcp, /*do_bind=*/false, 0xFFFF, 0);
        ASSERT_TRUE(sock.has_value());
        EXPECT_EQ(cfgCall(tp::kGidTcp, *sock, tp::kCfgMss, {0x02, 0x18}), tp::kRidEOk);  // 536
        // Wrong-length MSS paramVal (1 byte where the fixed(2) gate wants 2) -> E_INV.
        EXPECT_EQ(cfgCall(tp::kGidTcp, *sock, tp::kCfgMss, {0x05}), tp::kRidEInv);
        EXPECT_TRUE(testability::testabilityCloseSocket(cfg, tp::kGidTcp, *sock).eok());
    }
}

// CONNECT / SEND_DATA / CLOSE_SOCKET against an unknown socketId -> E_ISD.
TEST_F(TestabilityServerTest, UnknownSocketIdIsInvalid) {
    const auto cfg = loopbackConfig();
    const std::uint16_t bogus = 0xBEEF;
    EXPECT_EQ(testability::testabilityTcpConnect(cfg, bogus, 80, ::htonl(INADDR_LOOPBACK)).rid,
              tp::kRidEIsd);
    EXPECT_EQ(testability::testabilityTcpSendData(cfg, bogus, 1, 0, {0x01}).rid, tp::kRidEIsd);
    EXPECT_EQ(testability::testabilityCloseSocket(cfg, tp::kGidTcp, bogus).rid, tp::kRidEIsd);
}

// ── ICMP group (GID 0x03): ECHO_REQUEST (PRS_TPSP §6.10) ──

// Can this process open an ICMP socket at all?
//
// The server takes the unprivileged SOCK_DGRAM/IPPROTO_ICMP path when
// `net.ipv4.ping_group_range` admits our GID, and falls back to SOCK_RAW (which
// needs CAP_NET_RAW) when it does not. Where NEITHER is available there is no
// echo to emit, and the tests below would be asserting on the host's sysctl
// rather than on the server.
//
// This guard exists because that assumption was once written as a comment
// ("ping_group_range is open on CI / dev hosts") and nothing enforced it. The
// range resets to the restrictive default `1 0` on boot, so a runner reboot
// turned three tests red on a commit that touched none of this code — the gate
// blamed the change in front of it for a fact about the machine. A skip states
// what is actually true.
bool hasIcmpv4Socket() {
    // Same order the server tries, so the probe cannot pass where the server
    // would fail (or vice versa).
    for (const int type : {SOCK_DGRAM, SOCK_RAW}) {
        const int fd = ::socket(AF_INET, type | SOCK_CLOEXEC, IPPROTO_ICMP);
        if (fd >= 0) {
            ::close(fd);
            return true;
        }
    }
    return false;
}

// ECHO_REQUEST to loopback emits and reports E_OK.
TEST_F(TestabilityServerTest, IcmpEchoRequestToLoopbackReturnsEOk) {
    if (!hasIcmpv4Socket()) {
        GTEST_SKIP() << "no usable ICMPv4 socket on this host "
                        "(ping_group_range excludes this GID, no CAP_NET_RAW)";
    }
    const auto cfg = loopbackConfig();
    const std::vector<std::uint8_t> payload = {'p', 'i', 'n', 'g'};
    const auto r =
        testability::testabilityEchoRequest(cfg, /*iface=*/"", ::htonl(INADDR_LOOPBACK), payload);
    EXPECT_TRUE(r.eok()) << "ECHO_REQUEST to loopback should emit and report E_OK (rid="
                         << static_cast<int>(r.rid) << ")";
}

// An empty payload is valid (data vint8 n=0): a bare Echo Request still emits.
TEST_F(TestabilityServerTest, IcmpEchoRequestEmptyPayloadReturnsEOk) {
    if (!hasIcmpv4Socket()) {
        GTEST_SKIP() << "no usable ICMPv4 socket on this host "
                        "(ping_group_range excludes this GID, no CAP_NET_RAW)";
    }
    const auto cfg = loopbackConfig();
    const auto r = testability::testabilityEchoRequest(cfg, /*iface=*/"", ::htonl(INADDR_LOOPBACK), {});
    EXPECT_TRUE(r.eok()) << "rid=" << static_cast<int>(r.rid);
}

// An unknown interface name maps to the spec's E_IIF (PRS_TPSP §6.8). Relies on
// unprivileged SO_BINDTODEVICE returning ENODEV (Linux >= 5.7).
TEST_F(TestabilityServerTest, IcmpEchoRequestInvalidInterfaceReturnsEIif) {
    if (!hasIcmpv4Socket()) {
        GTEST_SKIP() << "no usable ICMPv4 socket on this host "
                        "(ping_group_range excludes this GID, no CAP_NET_RAW)";
    }
    const auto cfg = loopbackConfig();
    const auto r = testability::testabilityEchoRequest(cfg, /*iface=*/"tc8-no-such-if",
                                                    ::htonl(INADDR_LOOPBACK), {});
    EXPECT_TRUE(r.ok);  // the SP itself round-tripped
    EXPECT_EQ(r.rid, tp::kRidEIif) << "unknown interface should map to E_IIF";
}

// ── ICMPv6 group (GID 0x04): ECHO_REQUEST (PRS_TPSP §6.10) ──

// A 4-byte (IPv4-length) destAddr to the ICMPv6 group is malformed: the v6 echo
// requires a 16-byte ipxaddr. This rejection is pure dispatch + parse, so it
// holds regardless of whether the host has a usable IPv6 stack.
TEST_F(TestabilityServerTest, Icmpv6EchoRequestWrongAddrLengthReturnsEInv) {
    const auto cfg = loopbackConfig();
    std::vector<std::uint8_t> dat;
    tp::appendText(dat, "");                            // ifName
    tp::appendIpv4Addr(dat, ::htonl(INADDR_LOOPBACK));  // 4-byte addr — wrong for ICMPv6
    tp::appendVint8(dat, nullptr, 0);                   // data
    EXPECT_EQ(testability::testabilityCall(cfg, tp::kGidIcmpv6, tp::kPidEchoRequest, dat).rid,
              tp::kRidEInv);
}

// The ICMPv6 group defines only ECHO_REQUEST; any other PID is E_NTF.
TEST_F(TestabilityServerTest, Icmpv6UnknownPrimitiveReturnsENtf) {
    const auto cfg = loopbackConfig();
    EXPECT_EQ(testability::testabilityCall(cfg, tp::kGidIcmpv6, /*pid=*/0x7E, {}).rid, tp::kRidENtf);
}

// True if this host can open an ICMPv6 socket (the same acquisition the backend
// does). Where it cannot, the emit tests below would exercise the environment's
// lack of IPv6 rather than the endpoint, so they skip instead of failing.
static bool hasIcmpv6Socket() {
    int s = ::socket(AF_INET6, SOCK_DGRAM, IPPROTO_ICMPV6);
    if (s < 0) {
        s = ::socket(AF_INET6, SOCK_RAW, IPPROTO_ICMPV6);
    }
    if (s < 0) {
        return false;
    }
    ::close(s);
    return true;
}

// ECHO_REQUEST to the IPv6 loopback (::1) emits and reports E_OK where the host
// has a usable ICMPv6 socket (ping_group_range governs ICMPv6 ping sockets too,
// the IPv6 analog of the IPv4 echo case above).
TEST_F(TestabilityServerTest, Icmpv6EchoRequestToLoopbackReturnsEOk) {
    if (!hasIcmpv6Socket()) {
        GTEST_SKIP() << "no usable ICMPv6 socket on this host";
    }
    const auto cfg = loopbackConfig();
    const std::uint8_t loop6[16] = {0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1};  // ::1
    const std::vector<std::uint8_t> payload = {'p', 'i', 'n', 'g', '6'};
    const auto r = testability::testabilityEchoRequestV6(cfg, /*iface=*/"", loop6, payload);
    EXPECT_TRUE(r.eok()) << "ICMPv6 ECHO_REQUEST to ::1 should emit and report E_OK (rid="
                         << static_cast<int>(r.rid) << ")";
}

// An unknown interface name maps to the spec's E_IIF on the IPv6 path too
// (SO_BINDTODEVICE ENODEV), mirroring the IPv4 echo.
TEST_F(TestabilityServerTest, Icmpv6EchoRequestInvalidInterfaceReturnsEIif) {
    if (!hasIcmpv6Socket()) {
        GTEST_SKIP() << "no usable ICMPv6 socket on this host";
    }
    const auto cfg = loopbackConfig();
    const std::uint8_t loop6[16] = {0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1};  // ::1
    const auto r =
        testability::testabilityEchoRequestV6(cfg, /*iface=*/"tc8-no-such-if", loop6, {});
    EXPECT_TRUE(r.ok);  // the SP itself round-tripped
    EXPECT_EQ(r.rid, tp::kRidEIif) << "unknown interface should map to E_IIF";
}

// ── ETH group (GID 0x0B): INTERFACE_UP / INTERFACE_DOWN (PRS_TPSP §6.10) ──

// An unknown interface name maps to the spec's E_IIF: the SIOCGIFFLAGS read
// returns ENODEV before any privileged write, so this holds on an unprivileged
// CI host (no link-state change is attempted).
TEST_F(TestabilityServerTest, EthInterfaceUpInvalidInterfaceReturnsEIif) {
    const auto cfg = loopbackConfig();
    const auto r = testability::testabilityInterfaceUp(cfg, /*iface=*/"tc8-no-such-if");
    EXPECT_TRUE(r.ok);  // the SP itself round-tripped
    EXPECT_EQ(r.rid, tp::kRidEIif) << "unknown interface should map to E_IIF";
}

TEST_F(TestabilityServerTest, EthInterfaceDownInvalidInterfaceReturnsEIif) {
    const auto cfg = loopbackConfig();
    const auto r = testability::testabilityInterfaceDown(cfg, /*iface=*/"tc8-no-such-if");
    EXPECT_TRUE(r.ok);
    EXPECT_EQ(r.rid, tp::kRidEIif) << "unknown interface should map to E_IIF";
}

// A request with no parameters at all (missing the ifName text) is malformed
// -> E_INV, distinct from an empty-but-present ifName (which reaches the backend
// and resolves to E_IIF).
TEST_F(TestabilityServerTest, EthInterfaceUpMissingIfNameReturnsEInv) {
    const auto cfg = loopbackConfig();
    EXPECT_EQ(testability::testabilityCall(cfg, tp::kGidEth, tp::kPidInterfaceUp, {}).rid,
              tp::kRidEInv);
}

// The ETH group defines only INTERFACE_UP / INTERFACE_DOWN; any other PID is E_NTF.
TEST_F(TestabilityServerTest, EthUnknownPrimitiveReturnsENtf) {
    const auto cfg = loopbackConfig();
    EXPECT_EQ(testability::testabilityCall(cfg, tp::kGidEth, /*pid=*/0x7E, {}).rid, tp::kRidENtf);
}

// True if this process may change a link's administrative state. Probed by
// writing loopback's CURRENT flags straight back via SIOCSIFFLAGS — a genuine
// no-op that never brings an interface down. Where it cannot (no CAP_NET_ADMIN),
// the E_OK emit test would exercise the host's lack of privilege rather than the
// endpoint, so it skips instead of failing (mirrors hasIcmpv6Socket()).
static bool canSetLinkState() {
    int s = ::socket(AF_INET, SOCK_DGRAM, 0);
    if (s < 0) {
        return false;
    }
    ifreq ifr{};
    std::strncpy(ifr.ifr_name, "lo", IFNAMSIZ - 1);
    bool ok = false;
    if (::ioctl(s, SIOCGIFFLAGS, &ifr) == 0) {
        ok = ::ioctl(s, SIOCSIFFLAGS, &ifr) == 0;  // write the same flags back: a true no-op
    }
    ::close(s);
    return ok;
}

// Bringing loopback "up" while it is already up is an idempotent no-op that
// reports E_OK where the process holds CAP_NET_ADMIN. The destructive direction
// (INTERFACE_DOWN) would sever loopback for this very server, so it is left to
// the LIVE netns sweep; here only the non-destructive up-path is asserted.
TEST_F(TestabilityServerTest, EthInterfaceUpLoopbackReturnsEOk) {
    if (!canSetLinkState()) {
        GTEST_SKIP() << "no CAP_NET_ADMIN to change link state on this host";
    }
    const auto cfg = loopbackConfig();
    const auto r = testability::testabilityInterfaceUp(cfg, /*iface=*/"lo");
    EXPECT_TRUE(r.eok()) << "INTERFACE_UP on already-up loopback should report E_OK (rid="
                         << static_cast<int>(r.rid) << ")";
}

// ── PRS_TPSP §6.10 IP group (0x05) STATIC_ADDRESS / STATIC_ROUTE ──
//
// The privileged write (SIOCSIFADDR / SIOCADDRT) would mutate this host's
// addressing / routing, so only the non-mutating error paths are unit-tested here;
// the E_OK assignment path is left to the LIVE netns sweep. Each backend resolves
// the interface unprivileged FIRST, so an unknown one is E_IIF on any host.

TEST_F(TestabilityServerTest, IpStaticAddressInvalidInterfaceReturnsEIif) {
    const auto cfg = loopbackConfig();
    const auto r = testability::testabilityStaticAddress(cfg, /*iface=*/"tc8-no-such-if",
                                                      ::htonl(0x0A000001), /*cidr=*/24);
    EXPECT_TRUE(r.ok);  // the SP itself round-tripped
    EXPECT_EQ(r.rid, tp::kRidEIif) << "unknown interface should map to E_IIF";
}

TEST_F(TestabilityServerTest, IpStaticRouteInvalidInterfaceReturnsEIif) {
    const auto cfg = loopbackConfig();
    const auto r = testability::testabilityStaticRoute(cfg, /*iface=*/"tc8-no-such-if",
                                                    ::htonl(0x0A000000), /*cidr=*/24,
                                                    ::htonl(0x0A0000FE));
    EXPECT_TRUE(r.ok);
    EXPECT_EQ(r.rid, tp::kRidEIif) << "unknown interface should map to E_IIF";
}

// STATIC_ROUTE's parser has three malformed-input E_INV branches beyond the ifName: a
// wrong-length subNet, a missing netMask, and a wrong-length gateway. Each is pinned so
// a copy-paste error in a length gate (4 vs 16) cannot pass silently.
TEST_F(TestabilityServerTest, IpStaticRouteWrongSubnetLengthReturnsEInv) {
    const auto cfg = loopbackConfig();
    std::vector<std::uint8_t> dat;
    tp::appendText(dat, "lo");
    const std::uint8_t subnet16[16] = {};
    tp::appendIpv6Addr(dat, subnet16);  // 16-byte subNet under the IPv4 GID
    dat.push_back(24);                  // netMask
    tp::appendIpv4Addr(dat, ::htonl(0x0A0000FE));
    EXPECT_EQ(testability::testabilityCall(cfg, tp::kGidIp, tp::kPidStaticRoute, dat).rid,
              tp::kRidEInv);
}

TEST_F(TestabilityServerTest, IpStaticRouteMissingNetMaskReturnsEInv) {
    const auto cfg = loopbackConfig();
    std::vector<std::uint8_t> dat;
    tp::appendText(dat, "lo");
    tp::appendIpv4Addr(dat, ::htonl(0x0A000000));  // subNet, then truncate (no netMask)
    EXPECT_EQ(testability::testabilityCall(cfg, tp::kGidIp, tp::kPidStaticRoute, dat).rid,
              tp::kRidEInv);
}

TEST_F(TestabilityServerTest, IpStaticRouteWrongGatewayLengthReturnsEInv) {
    const auto cfg = loopbackConfig();
    std::vector<std::uint8_t> dat;
    tp::appendText(dat, "lo");
    tp::appendIpv4Addr(dat, ::htonl(0x0A000000));  // subNet (n=4, valid)
    dat.push_back(24);                             // netMask
    const std::uint8_t gw16[16] = {};
    tp::appendIpv6Addr(dat, gw16);                 // 16-byte gateway under the IPv4 GID
    EXPECT_EQ(testability::testabilityCall(cfg, tp::kGidIp, tp::kPidStaticRoute, dat).rid,
              tp::kRidEInv);
}

// A request with no parameters at all (missing the ifName text) is malformed -> E_INV.
TEST_F(TestabilityServerTest, IpStaticAddressMissingParamsReturnsEInv) {
    const auto cfg = loopbackConfig();
    EXPECT_EQ(testability::testabilityCall(cfg, tp::kGidIp, tp::kPidStaticAddress, {}).rid,
              tp::kRidEInv);
}

// STATIC_ADDRESS under the IPv4 group accepts only an n=4 ipxaddr; a 16-byte (IPv6)
// address is E_INV — IPv6 STATIC_ADDRESS is the separate GID 0x06.
TEST_F(TestabilityServerTest, IpStaticAddressWrongAddrLengthReturnsEInv) {
    const auto cfg = loopbackConfig();
    std::vector<std::uint8_t> dat;
    tp::appendText(dat, "lo");        // ifName
    const std::uint8_t addr16[16] = {};
    tp::appendIpv6Addr(dat, addr16);  // 16-byte addr under the IPv4 GID
    dat.push_back(24);                // netMask
    EXPECT_EQ(testability::testabilityCall(cfg, tp::kGidIp, tp::kPidStaticAddress, dat).rid,
              tp::kRidEInv);
}

// The IP group defines only STATIC_ADDRESS / STATIC_ROUTE; any other PID is E_NTF.
TEST_F(TestabilityServerTest, IpUnknownPrimitiveReturnsENtf) {
    const auto cfg = loopbackConfig();
    EXPECT_EQ(testability::testabilityCall(cfg, tp::kGidIp, /*pid=*/0x7E, {}).rid, tp::kRidENtf);
}

// A CIDR prefix > 32 is invalid input -> E_INV, returned by the backend BEFORE it
// resolves the interface or issues any ioctl, so this is host-safe even naming a
// real interface ("lo" is never touched).
TEST_F(TestabilityServerTest, IpStaticAddressBadCidrReturnsEInv) {
    const auto cfg = loopbackConfig();
    const auto r = testability::testabilityStaticAddress(cfg, /*iface=*/"lo",
                                                      ::htonl(0x7F000002), /*cidr=*/33);
    EXPECT_EQ(r.rid, tp::kRidEInv) << "cidr > 32 should be E_INV";
}

// The valid maximum prefix (/32) must PASS the range guard — pinned via an unknown
// interface so no privileged write is attempted: cidr 32 clears the `> 32` guard and the
// unknown iface yields E_IIF (an off-by-one `>= 32` would wrongly return E_INV here).
TEST_F(TestabilityServerTest, IpStaticAddressCidr32PassesGuardReturnsEIif) {
    const auto cfg = loopbackConfig();
    const auto r = testability::testabilityStaticAddress(cfg, /*iface=*/"tc8-no-such-if",
                                                      ::htonl(0x0A000001), /*cidr=*/32);
    EXPECT_EQ(r.rid, tp::kRidEIif) << "cidr == 32 is valid and should pass to E_IIF";
}

// ── PRS_TPSP §6.10 IPv6 group (GID 0x06): STATIC_ADDRESS / STATIC_ROUTE ──
// The IPv6 mirror of the IP group above. The privileged write (SIOCSIFADDR /
// SIOCADDRT with an in6_ifreq / in6_rtmsg) would mutate this host's addressing /
// routing, so only the non-mutating error paths are unit-tested here; the E_OK path
// is left to the LIVE netns check. 2001:db8::/32 is the RFC 3849 documentation prefix.

TEST_F(TestabilityServerTest, Ipv6StaticAddressInvalidInterfaceReturnsEIif) {
    const auto cfg = loopbackConfig();
    const std::uint8_t addr16[16] = {0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0,
                                     0,    0,    0,    0,    0, 0, 0, 0x01};
    const auto r = testability::testabilityStaticAddressV6(cfg, /*iface=*/"tc8-no-such-if", addr16,
                                                        /*prefix=*/64);
    EXPECT_TRUE(r.ok);  // the SP itself round-tripped
    EXPECT_EQ(r.rid, tp::kRidEIif) << "unknown interface should map to E_IIF";
}

TEST_F(TestabilityServerTest, Ipv6StaticRouteInvalidInterfaceReturnsEIif) {
    const auto cfg = loopbackConfig();
    const std::uint8_t subnet16[16] = {0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0};
    const std::uint8_t gw16[16] = {0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0,
                                   0,    0,    0,    0,    0, 0, 0, 0x01};
    const auto r = testability::testabilityStaticRouteV6(cfg, /*iface=*/"tc8-no-such-if", subnet16,
                                                      /*prefix=*/64, gw16);
    EXPECT_TRUE(r.ok);
    EXPECT_EQ(r.rid, tp::kRidEIif) << "unknown interface should map to E_IIF";
}

// STATIC_ROUTE's parser has the same three malformed-input E_INV branches as the IPv4
// route above (wrong-length subNet, missing netMask, wrong-length gateway), pinned so a
// length-gate copy-paste error (16 vs 4) cannot pass silently.
TEST_F(TestabilityServerTest, Ipv6StaticRouteWrongSubnetLengthReturnsEInv) {
    const auto cfg = loopbackConfig();
    std::vector<std::uint8_t> dat;
    tp::appendText(dat, "lo");
    tp::appendIpv4Addr(dat, ::htonl(0x7F000001));  // 4-byte subNet under the IPv6 GID
    dat.push_back(64);                             // netMask
    const std::uint8_t gw16[16] = {};
    tp::appendIpv6Addr(dat, gw16);
    EXPECT_EQ(testability::testabilityCall(cfg, tp::kGidIpv6, tp::kPidStaticRoute, dat).rid,
              tp::kRidEInv);
}

TEST_F(TestabilityServerTest, Ipv6StaticRouteMissingNetMaskReturnsEInv) {
    const auto cfg = loopbackConfig();
    std::vector<std::uint8_t> dat;
    tp::appendText(dat, "lo");
    const std::uint8_t subnet16[16] = {};
    tp::appendIpv6Addr(dat, subnet16);  // subNet, then truncate (no netMask)
    EXPECT_EQ(testability::testabilityCall(cfg, tp::kGidIpv6, tp::kPidStaticRoute, dat).rid,
              tp::kRidEInv);
}

TEST_F(TestabilityServerTest, Ipv6StaticRouteWrongGatewayLengthReturnsEInv) {
    const auto cfg = loopbackConfig();
    std::vector<std::uint8_t> dat;
    tp::appendText(dat, "lo");
    const std::uint8_t subnet16[16] = {};
    tp::appendIpv6Addr(dat, subnet16);             // subNet (n=16, valid)
    dat.push_back(64);                             // netMask
    tp::appendIpv4Addr(dat, ::htonl(0x7F000001));  // 4-byte gateway under the IPv6 GID
    EXPECT_EQ(testability::testabilityCall(cfg, tp::kGidIpv6, tp::kPidStaticRoute, dat).rid,
              tp::kRidEInv);
}

// A request with no parameters at all (missing the ifName text) is malformed -> E_INV.
TEST_F(TestabilityServerTest, Ipv6StaticAddressMissingParamsReturnsEInv) {
    const auto cfg = loopbackConfig();
    EXPECT_EQ(testability::testabilityCall(cfg, tp::kGidIpv6, tp::kPidStaticAddress, {}).rid,
              tp::kRidEInv);
}

// STATIC_ADDRESS under the IPv6 group accepts only an n=16 ipxaddr; a 4-byte (IPv4)
// address is E_INV — IPv4 STATIC_ADDRESS is the separate GID 0x05.
TEST_F(TestabilityServerTest, Ipv6StaticAddressWrongAddrLengthReturnsEInv) {
    const auto cfg = loopbackConfig();
    std::vector<std::uint8_t> dat;
    tp::appendText(dat, "lo");                          // ifName
    tp::appendIpv4Addr(dat, ::htonl(0x7F000001));       // 4-byte addr under the IPv6 GID
    dat.push_back(64);                                  // netMask
    EXPECT_EQ(testability::testabilityCall(cfg, tp::kGidIpv6, tp::kPidStaticAddress, dat).rid,
              tp::kRidEInv);
}

// The IPv6 group defines only STATIC_ADDRESS / STATIC_ROUTE; any other PID is E_NTF.
TEST_F(TestabilityServerTest, Ipv6UnknownPrimitiveReturnsENtf) {
    const auto cfg = loopbackConfig();
    EXPECT_EQ(testability::testabilityCall(cfg, tp::kGidIpv6, /*pid=*/0x7E, {}).rid, tp::kRidENtf);
}

// A prefix length > 128 is invalid input -> E_INV, returned by the backend BEFORE it
// resolves the interface or issues any ioctl, so this is host-safe even naming a real
// interface ("lo" is never touched).
TEST_F(TestabilityServerTest, Ipv6StaticAddressBadPrefixReturnsEInv) {
    const auto cfg = loopbackConfig();
    const std::uint8_t addr16[16] = {0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0,
                                     0,    0,    0,    0,    0, 0, 0, 0x02};
    const auto r = testability::testabilityStaticAddressV6(cfg, /*iface=*/"lo", addr16,
                                                        /*prefix=*/129);
    EXPECT_EQ(r.rid, tp::kRidEInv) << "prefix > 128 should be E_INV";
}

// The valid maximum prefix (/128, an IPv6 host route) must PASS the range guard — pinned
// via an unknown interface (prefix 128 clears the `> 128` guard, the unknown iface yields
// E_IIF). An off-by-one `>= 128` would wrongly return E_INV here. Host-safe.
TEST_F(TestabilityServerTest, Ipv6StaticAddressPrefix128PassesGuardReturnsEIif) {
    const auto cfg = loopbackConfig();
    const std::uint8_t addr16[16] = {0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0,
                                     0,    0,    0,    0,    0, 0, 0, 0x03};
    const auto r = testability::testabilityStaticAddressV6(cfg, /*iface=*/"tc8-no-such-if", addr16,
                                                        /*prefix=*/128);
    EXPECT_EQ(r.rid, tp::kRidEIif) << "prefix == 128 is valid and should pass to E_IIF";
}

// ── PRS_TPSP §6.6 OEM extension / override seam (registerPrimitive) ──

// EXTEND: a registered handler for a non-standard group the core knows nothing
// about (GID 0x7F, counted down per PRS_TPSP §6.6) is dispatched with the parsed
// request and its DAT, and its Result ID + response DAT reach the caller.
TEST(TestabilityServerSeamTest, OemHandlerExtendsNonStandardGroup) {
    constexpr std::uint16_t kPort = 31711;
    TC8_STATIC_ASSERT_TEST_PORT(kPort);
    constexpr std::uint8_t kVendorGid = 0x7F;
    constexpr std::uint8_t kVendorPid = 0x2A;

    testability::ProtocolServer server{std::make_unique<dut::LinuxSocketBackend>()};
    server.registerPrimitive(
        kVendorGid, kVendorPid,
        [](const tp::Header &, const std::uint8_t *dat, std::size_t dat_len, const tc8::net::Endpoint &,
           std::uint8_t &rid, std::vector<std::uint8_t> &resp) {
            resp.push_back(0xA5);  // tag proving the handler ran
            resp.insert(resp.end(), dat, dat + dat_len);  // echo the request DAT back
            rid = tp::kRidEOk;
        });
    ASSERT_TRUE(server.start(kPort));

    testability::TestabilityConfig cfg;
    cfg.dut_ip_be = ::htonl(INADDR_LOOPBACK);
    cfg.dut_port = kPort;
    const std::vector<std::uint8_t> req = {0x01, 0x02, 0x03};
    const auto r = testability::testabilityCall(cfg, kVendorGid, kVendorPid, req);
    server.stop();

    ASSERT_TRUE(r.ok);
    EXPECT_EQ(r.rid, tp::kRidEOk);
    ASSERT_EQ(r.dat.size(), req.size() + 1);
    EXPECT_EQ(r.dat[0], 0xA5u);
    EXPECT_EQ(r.dat[1], 0x01u);
    EXPECT_EQ(r.dat[3], 0x03u);
}

// OVERRIDE: a registered handler for a built-in standard primitive (GENERAL
// GET_VERSION) wins over the core implementation.
TEST(TestabilityServerSeamTest, OemHandlerOverridesStandardPrimitive) {
    constexpr std::uint16_t kPort = 31712;
    TC8_STATIC_ASSERT_TEST_PORT(kPort);

    testability::ProtocolServer server{std::make_unique<dut::LinuxSocketBackend>()};
    server.registerPrimitive(
        tp::kGidGeneral, tp::kPidGetVersion,
        [](const tp::Header &, const std::uint8_t *, std::size_t, const tc8::net::Endpoint &,
           std::uint8_t &rid, std::vector<std::uint8_t> &resp) {
            tp::appendU16(resp, 9);  // a version the built-in never reports (1.2.0)
            tp::appendU16(resp, 9);
            tp::appendU16(resp, 9);
            rid = tp::kRidEOk;
        });
    ASSERT_TRUE(server.start(kPort));

    testability::TestabilityConfig cfg;
    cfg.dut_ip_be = ::htonl(INADDR_LOOPBACK);
    cfg.dut_port = kPort;
    const auto v = testability::testabilityGetVersion(cfg);
    server.stop();

    ASSERT_TRUE(v.has_value());
    EXPECT_EQ(v->major, 9u);  // the vendor override, not kVersionMajor
    EXPECT_EQ(v->minor, 9u);
    EXPECT_EQ(v->patch, 9u);
}

// Single-task entry (startInline): no owned thread — the caller pumps runOnce().
// This is the bare-metal / RTOS shape. Drive it entirely on the test thread:
// queue a request, pump the reactor, and read the response back, all single-
// threaded, proving the endpoint serves without any std::thread of its own.
TEST(TestabilityServerSeamTest, InlineSingleTaskServerAnswersOnCallerPump) {
    constexpr std::uint16_t kPort = 31799;
    TC8_STATIC_ASSERT_TEST_PORT(kPort);

    testability::ProtocolServer server{std::make_unique<dut::LinuxSocketBackend>()};
    ASSERT_TRUE(server.startInline(kPort));  // no reactor thread; this test IS the loop

    dut::LinuxSocketBackend client;
    const int cfd = client.createUdp();
    ASSERT_GE(cfd, 0);
    client.setNonBlocking(cfd, true);  // poll it via the pump, never block the single task

    tp::Header h;
    h.method_id = tp::methodId(tp::kGidGeneral, tp::kPidGetVersion);
    const auto msg = tp::buildMessage(h);
    const tc8::net::Endpoint dst{::htonl(INADDR_LOOPBACK), kPort};
    client.sendToV4(cfd, msg.data(), msg.size(), dst);

    std::uint8_t rb[256];
    tc8::net::Endpoint src{};
    int rn = -1;
    const auto deadline = std::chrono::steady_clock::now() + std::chrono::milliseconds{2000};
    while (std::chrono::steady_clock::now() < deadline) {
        server.runOnce(/*timeout_ms=*/5);  // the caller-driven single-task pump
        rn = client.recvFromV4(cfd, rb, sizeof(rb), src);
        if (rn >= static_cast<int>(tp::kHeaderSize)) {
            break;
        }
    }
    server.stop();
    client.closeFd(cfd);

    ASSERT_GE(rn, static_cast<int>(tp::kHeaderSize)) << "inline server answered on the caller pump";
    const auto rh = tp::parseHeader(rb, static_cast<std::size_t>(rn));
    ASSERT_TRUE(rh.has_value());
    EXPECT_EQ(rh->tid, tp::kTidResponse);
    EXPECT_EQ(rh->rid, tp::kRidEOk);
}

// ── Stateful middleware seam (registerModule, PRS_TPSP §6.6) ──
//
// A synthetic module owning an OEM-reserved GID (non-standard groups count down
// from 0x7F) exercises the registerModule path: a routed/echoed primitive, an
// unknown PID, a periodic timer advancing state on the module executor, END_TEST
// reset, and an asynchronous Event from a one-shot timer.

constexpr std::uint8_t kProbeGid = 0x7F;
constexpr std::uint8_t kProbePidEcho = 0x01;
constexpr std::uint8_t kProbePidArmTick = 0x02;
constexpr std::uint8_t kProbePidReadCount = 0x03;
constexpr std::uint8_t kProbePidArmEvent = 0x04;
constexpr std::uint8_t kProbePidArmRx = 0x05;    // open+bind a data socket, watchReadable it
constexpr std::uint8_t kProbePidReadRx = 0x06;   // return the last datagram the watch consumed
constexpr std::uint16_t kProbeRxPort = 31902;    // the module's data-plane UDP port
TC8_STATIC_ASSERT_TEST_PORT(kProbeRxPort);
constexpr std::size_t kProbeRxBufLen = 256;      // inbound datagram read buffer

class SeamProbeModule : public testability::MiddlewareModule {
public:
    std::vector<std::uint8_t> groups() const override { return {kProbeGid}; }
    void onStart(testability::MiddlewareContext &ctx) override { ctx_ = &ctx; }
    void onStop() override {
        if (ctx_ != nullptr) {
            ctx_->unwatch(rx_watch_);
            if (rx_sock_ >= 0) {
                ctx_->backend().closeFd(rx_sock_);
                rx_sock_ = -1;
            }
        }
    }
    void onEndTest() override {
        if (tick_timer_ != testability::kNoTimer) {
            ctx_->cancel(tick_timer_);
            tick_timer_ = testability::kNoTimer;
        }
        tick_count_ = 0;  // executor thread — single-threaded, no lock
    }
    void onPrimitive(const tp::Header &req, const std::uint8_t *dat, std::size_t dat_len,
                     const tc8::net::Endpoint &, std::uint8_t &rid,
                     std::vector<std::uint8_t> &resp) override {
        switch (tp::pidOf(req.method_id)) {
            case kProbePidEcho:
                resp.assign(dat, dat + dat_len);
                rid = tp::kRidEOk;
                return;
            case kProbePidArmTick:
                tick_timer_ = ctx_->scheduleEvery(std::chrono::milliseconds(5),
                                                  [this] { ++tick_count_; });
                rid = tp::kRidEOk;
                return;
            case kProbePidReadCount:
                tp::appendU16(resp, static_cast<std::uint16_t>(tick_count_));
                rid = tp::kRidEOk;
                return;
            case kProbePidArmEvent:
                ctx_->scheduleOnce(std::chrono::milliseconds(5), [this] {
                    const std::vector<std::uint8_t> ev = {0xAB, 0xCD};
                    ctx_->emitEvent(kProbeGid, kProbePidArmEvent, ev);
                });
                rid = tp::kRidEOk;
                return;
            case kProbePidArmRx:
                // Open the data plane and register it with the reactor — all on the
                // executor, so no lock guards rx_sock_ / rx_watch_ / last_rx_.
                rx_sock_ = ctx_->backend().createUdp();
                if (rx_sock_ >= 0 && ctx_->backend().bindV4(rx_sock_, 0, kProbeRxPort)) {
                    rx_watch_ = ctx_->watchReadable(rx_sock_, [this] { onRx(); });
                    rid = tp::kRidEOk;
                } else {
                    rid = tp::kRidENok;
                }
                return;
            case kProbePidReadRx:
                resp = last_rx_;  // executor thread — same thread as onRx, no lock
                rid = tp::kRidEOk;
                return;
            default:
                rid = tp::kRidENtf;
                return;
        }
    }

private:
    // Reactor-delivered: a datagram is readable on rx_sock_. Drain one and record
    // it so kProbePidReadRx can read it back. Level-triggered: must consume.
    void onRx() {
        std::uint8_t buf[kProbeRxBufLen];
        tc8::net::Endpoint src{};
        const int n = ctx_->backend().recvFromV4(rx_sock_, buf, sizeof(buf), src);
        if (n > 0) {
            last_rx_.assign(buf, buf + n);
        }
    }

    testability::MiddlewareContext *ctx_ = nullptr;
    testability::TimerId tick_timer_ = testability::kNoTimer;
    std::uint32_t tick_count_ = 0;
    int rx_sock_ = -1;
    testability::WatchId rx_watch_ = testability::kNoWatch;
    std::vector<std::uint8_t> last_rx_;
};

// A module that (illegally) claims the core GENERAL group — for the fail-fast test.
class CoreGidModule : public testability::MiddlewareModule {
public:
    std::vector<std::uint8_t> groups() const override { return {tp::kGidGeneral}; }
    void onStart(testability::MiddlewareContext &) override {}
    void onStop() override {}
    void onPrimitive(const tp::Header &, const std::uint8_t *, std::size_t,
                     const tc8::net::Endpoint &, std::uint8_t &rid,
                     std::vector<std::uint8_t> &) override {
        rid = tp::kRidENtf;
    }
};

testability::TestabilityConfig loopbackOn(std::uint16_t port) {
    testability::TestabilityConfig cfg;
    cfg.dut_ip_be = ::htonl(INADDR_LOOPBACK);
    cfg.dut_port = port;
    return cfg;
}

// One server hosting a synthetic module on a loopback control channel per test.
class MiddlewareSeamTest : public ::testing::Test {
protected:
    void SetUp() override {
        server_.registerModule(std::make_unique<SeamProbeModule>());
        ASSERT_TRUE(server_.start(kPort));
        cfg_ = loopbackOn(kPort);
    }
    void TearDown() override { server_.stop(); }

    // Poll the module's tick counter until it is > 0 or a 2 s deadline — replaces
    // a fixed sleep so a saturated host cannot false-fail (executor timers are
    // best-effort under load; the repo has a timing-flake history).
    int pollCounterPositive() {
        const auto deadline = std::chrono::steady_clock::now() + std::chrono::seconds(2);
        int v = 0;
        do {
            const auto r = testability::testabilityCall(cfg_, kProbeGid, kProbePidReadCount, {});
            if (r.eok() && r.dat.size() == 2u) {
                v = (r.dat[0] << 8) | r.dat[1];
                if (v > 0) {
                    return v;
                }
            }
            std::this_thread::sleep_for(std::chrono::milliseconds(2));
        } while (std::chrono::steady_clock::now() < deadline);
        return v;
    }

    int readCount() {
        const auto r = testability::testabilityCall(cfg_, kProbeGid, kProbePidReadCount, {});
        EXPECT_TRUE(r.eok());
        EXPECT_EQ(r.dat.size(), 2u);
        return r.dat.size() == 2u ? ((r.dat[0] << 8) | r.dat[1]) : -1;
    }

    static constexpr std::uint16_t kPort = 31901;
    TC8_STATIC_ASSERT_TEST_PORT(kPort);
    testability::ProtocolServer server_{std::make_unique<dut::LinuxSocketBackend>()};
    testability::TestabilityConfig cfg_;
};

TEST_F(MiddlewareSeamTest, PrimitiveRoutesEchoesAndUnknownPidIsNotFound) {
    const std::vector<std::uint8_t> body = {0x11, 0x22, 0x33};
    const auto echo = testability::testabilityCall(cfg_, kProbeGid, kProbePidEcho, body);
    EXPECT_TRUE(echo.eok());
    EXPECT_EQ(echo.dat, body);

    const auto unknown = testability::testabilityCall(cfg_, kProbeGid, 0xFE, {});
    EXPECT_TRUE(unknown.ok);
    EXPECT_EQ(unknown.rid, tp::kRidENtf);
}

TEST_F(MiddlewareSeamTest, TimerAdvancesStateAndEndTestResetsIt) {
    EXPECT_TRUE(testability::testabilityCall(cfg_, kProbeGid, kProbePidArmTick, {}).eok());
    EXPECT_GT(pollCounterPositive(), 0);  // periodic timer advanced the counter

    // END_TEST is synchronous (onEndTest awaited), so the count is cleared and the
    // timer cancelled by the time the Response returns — and stays so.
    EXPECT_TRUE(testability::testabilityEndTest(cfg_, /*tc_id=*/1, "demo").eok());
    EXPECT_EQ(readCount(), 0);
    std::this_thread::sleep_for(std::chrono::milliseconds(20));
    EXPECT_EQ(readCount(), 0);
}

TEST_F(MiddlewareSeamTest, EmitsAsyncEventToRequester) {
    // A persistent UDP socket as the test system so the async Event (sent to the
    // arm primitive's requester) reaches us — testabilityCall closes its socket
    // after the Response. The 1 s recv timeout makes the wait deadline-bounded,
    // not sleep-based.
    const int s = ::socket(AF_INET, SOCK_DGRAM, 0);
    ASSERT_GE(s, 0);
    sockaddr_in la{};
    la.sin_family = AF_INET;
    la.sin_addr.s_addr = ::htonl(INADDR_LOOPBACK);
    la.sin_port = 0;
    ASSERT_EQ(::bind(s, reinterpret_cast<sockaddr *>(&la), sizeof(la)), 0);
    timeval tv{};
    tv.tv_sec = 1;
    ::setsockopt(s, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));

    sockaddr_in dst{};
    dst.sin_family = AF_INET;
    dst.sin_addr.s_addr = ::htonl(INADDR_LOOPBACK);
    dst.sin_port = ::htons(kPort);

    tp::Header h;
    h.method_id = tp::methodId(kProbeGid, kProbePidArmEvent);
    h.tid = tp::kTidRequest;
    const auto req = tp::buildMessage(h, nullptr, 0);
    ASSERT_GT(::sendto(s, req.data(), req.size(), 0, reinterpret_cast<sockaddr *>(&dst),
                       sizeof(dst)),
              0);

    std::uint8_t buf[64];
    const int rn = ::recv(s, buf, sizeof(buf), 0);  // synchronous Response
    ASSERT_GE(rn, static_cast<int>(tp::kHeaderSize));
    const auto resp = tp::parseHeader(buf, static_cast<std::size_t>(rn));
    ASSERT_TRUE(resp.has_value());
    EXPECT_EQ(resp->tid, tp::kTidResponse);
    EXPECT_EQ(resp->rid, tp::kRidEOk);

    const int en = ::recv(s, buf, sizeof(buf), 0);  // async Event (~5 ms later)
    ASSERT_GE(en, static_cast<int>(tp::kHeaderSize));
    const auto ev = tp::parseHeader(buf, static_cast<std::size_t>(en));
    ASSERT_TRUE(ev.has_value());
    EXPECT_EQ(ev->tid, tp::kTidEvent);
    EXPECT_TRUE(tp::isEvent(ev->method_id));
    EXPECT_EQ(tp::gidOf(ev->method_id), kProbeGid);
    EXPECT_EQ(tp::pidOf(ev->method_id), kProbePidArmEvent);
    ASSERT_EQ(static_cast<std::size_t>(en) - tp::kHeaderSize, 2u);
    EXPECT_EQ(buf[tp::kHeaderSize], 0xABu);
    EXPECT_EQ(buf[tp::kHeaderSize + 1], 0xCDu);

    ::close(s);
}

// registerModule must fail fast on a clashing GID rather than silently shadow.
TEST(MiddlewareSeam, RegisterModuleRejectsDuplicateAndCoreGid) {
    testability::ProtocolServer server{std::make_unique<dut::LinuxSocketBackend>()};
    server.registerModule(std::make_unique<SeamProbeModule>());
    EXPECT_THROW(server.registerModule(std::make_unique<SeamProbeModule>()), std::invalid_argument);
    EXPECT_THROW(server.registerModule(std::make_unique<CoreGidModule>()), std::invalid_argument);
}

// The rx reactor end to end over real loopback sockets: ARM_RX opens a data
// socket and registers it via watchReadable; a datagram sent to that port is
// consumed by the module on its executor (genuine poll readiness, no drain
// timer) and read back through READ_RX. Because the module arms no timer, the
// executor blocks in poll() indefinitely — so the READ_RX primitive returning at
// all proves the cross-thread waker broke that poll (otherwise this would hang).
TEST_F(MiddlewareSeamTest, WatchReadableConsumesInboundDatagramOverLoopback) {
    ASSERT_TRUE(testability::testabilityCall(cfg_, kProbeGid, kProbePidArmRx, {}).eok());

    // Tester -> the module's data port.
    const int s = ::socket(AF_INET, SOCK_DGRAM, 0);
    ASSERT_GE(s, 0);
    sockaddr_in to{};
    to.sin_family = AF_INET;
    to.sin_addr.s_addr = ::htonl(INADDR_LOOPBACK);
    to.sin_port = htons(kProbeRxPort);
    const std::vector<std::uint8_t> payload = {0xDE, 0xAD, 0xBE, 0xEF};
    ASSERT_EQ(::sendto(s, payload.data(), payload.size(), 0,
                       reinterpret_cast<sockaddr *>(&to), sizeof(to)),
              static_cast<ssize_t>(payload.size()));
    ::close(s);

    // Poll READ_RX until it reflects the payload (rx is asynchronous) or a 2 s
    // deadline — a fixed sleep could false-fail a loaded host (timing-flake history).
    const auto deadline = std::chrono::steady_clock::now() + std::chrono::seconds(2);
    std::vector<std::uint8_t> got;
    do {
        const auto r = testability::testabilityCall(cfg_, kProbeGid, kProbePidReadRx, {});
        if (r.eok() && r.dat == payload) {
            got = r.dat;
            break;
        }
        std::this_thread::sleep_for(std::chrono::milliseconds(5));
    } while (std::chrono::steady_clock::now() < deadline);
    EXPECT_EQ(got, payload);
}

// joinMulticast (POSIX): a socket joined to an admin-scoped group receives a
// datagram sent to that group over the default interface (IP_MULTICAST_LOOP is on
// by default), proving the IP_ADD_MEMBERSHIP mapping with a real consumer — not
// just an E_OK. (The lwIP backend defers multicast; see lwip_socket_backend.cpp.)
TEST(PosixBackendMulticast, JoinMulticastReceivesGroupDatagram) {
    dut::LinuxSocketBackend be;
    constexpr std::uint16_t kMcPort = 31903;
    TC8_STATIC_ASSERT_TEST_PORT(kMcPort);
    const std::uint32_t group_be = ::htonl(0xEF010203);  // 239.1.2.3 (admin-scoped)

    const int rx = be.createUdp();
    ASSERT_GE(rx, 0);
    be.setReuseAddr(rx);
    be.setRecvTimeoutMs(rx, 2000);  // bound the recv so a non-multicast host cannot hang
    ASSERT_TRUE(be.bindV4(rx, 0, kMcPort));
    ASSERT_TRUE(be.joinMulticast(rx, group_be, 0))  // 0 = default interface
        << "IP_ADD_MEMBERSHIP failed";

    const int tx = be.createUdp();
    ASSERT_GE(tx, 0);
    const int loop_on = 1;  // ensure the sender's own host receives the multicast
    ::setsockopt(tx, IPPROTO_IP, IP_MULTICAST_LOOP, &loop_on, sizeof(loop_on));

    const std::vector<std::uint8_t> payload = {0x4D, 0x43, 0x41, 0x53, 0x54};  // "MCAST"
    tc8::net::Endpoint grp{group_be, kMcPort};
    ASSERT_EQ(be.sendToV4(tx, payload.data(), payload.size(), grp),
              static_cast<int>(payload.size()));

    std::uint8_t buf[64];
    tc8::net::Endpoint src{};
    const int n = be.recvFromV4(rx, buf, sizeof(buf), src);
    ASSERT_EQ(n, static_cast<int>(payload.size())) << "joined group datagram not received";
    EXPECT_EQ(std::vector<std::uint8_t>(buf, buf + n), payload);

    // The leaveMulticast counterpart: dropping the membership succeeds.
    EXPECT_TRUE(be.leaveMulticast(rx, group_be, 0)) << "IP_DROP_MEMBERSHIP failed";

    be.closeFd(tx);
    be.closeFd(rx);
}

// flushDynamicArp (POSIX): an unknown interface is rejected, and a real interface
// with no learned entries flushes successfully (loopback has no dynamic neighbors,
// so this needs no CAP_NET_ADMIN — the delete phase sends nothing). Flushing
// entries that actually exist is exercised under NET_ADMIN in the netns fixture.
TEST(PosixBackendArp, FlushDynamicArpResolvesInterfaceAndSucceedsOnEmpty) {
    dut::LinuxSocketBackend be;
    EXPECT_FALSE(be.flushDynamicArp("tc8_no_such_iface")) << "unknown interface must be rejected";
    EXPECT_TRUE(be.flushDynamicArp("lo")) << "flush on an entry-free interface should succeed";
}

// Neighbor ops (POSIX): each resolves the interface unprivileged FIRST (via
// if_nametoindex / the procfs path), so an unknown interface is rejected on any
// host, no CAP_NET_ADMIN needed.
TEST(PosixBackendNeighbor, UnknownInterfaceRejected) {
    dut::LinuxSocketBackend be;
    const std::uint8_t mac[6] = {0x02, 0x00, 0x00, 0x00, 0x00, 0x01};
    const std::uint32_t ip_be = ::htonl(0x0A000002);  // 10.0.0.2
    EXPECT_FALSE(be.addStaticNeighbor("tc8_no_such_iface", ip_be, mac));
    EXPECT_FALSE(be.removeNeighbor("tc8_no_such_iface", ip_be));
    EXPECT_FALSE(be.setNeighborReachableMs("tc8_no_such_iface", 30000));
}

// Where the process holds CAP_NET_ADMIN, the writes themselves are exercised on
// loopback (harmless: lo has the neigh sysctls and no real neighbors). The aging
// sysctl round-trips its value, and a per-IP delete of an absent entry is success
// (idempotent). Without privilege the test skips rather than asserting the host's
// lack of it (mirrors EthInterfaceUpLoopbackReturnsEOk).
TEST(PosixBackendNeighbor, PrivilegedWritesOnLoopback) {
    if (!hasNetAdmin()) {
        GTEST_SKIP() << "neighbor writes need CAP_NET_ADMIN on this host";
    }
    dut::LinuxSocketBackend be;
    constexpr const char *kPath = "/proc/sys/net/ipv4/neigh/lo/base_reachable_time_ms";
    int original = 0;
    {
        std::ifstream in(kPath);
        ASSERT_TRUE(static_cast<bool>(in >> original)) << "could not read " << kPath;
    }
    // Restore lo's aging value at scope exit no matter how the test leaves (an
    // ASSERT below early-returns), so the host sysctl is never left mutated.
    ScopeExit restore([&] { be.setNeighborReachableMs("lo", original); });

    EXPECT_TRUE(be.setNeighborReachableMs("lo", 45000)) << "privileged aging write should succeed";
    int after = 0;
    {
        std::ifstream in(kPath);
        ASSERT_TRUE(static_cast<bool>(in >> after));
    }
    EXPECT_EQ(after, 45000) << "the aging time should read back as written";

    // Deleting an entry that does not exist is idempotent success (-ENOENT).
    EXPECT_TRUE(be.removeNeighbor("lo", ::htonl(0x0A0000FE)))
        << "removing an absent neighbor should succeed (idempotent)";
}

// addStaticNeighbor's success path needs an ARP-capable interface; loopback is
// NOARP, so create a dummy. This exercises the one neighbor message the loopback
// test cannot: RTM_NEWNEIGH carrying NUD_PERMANENT + an NDA_LLADDR. Runs wherever
// the process holds CAP_NET_ADMIN — including the no-sudo `unshare` netns the
// posix_neighbor_privileged CTest uses — else it skips.
TEST(PosixBackendNeighbor, PrivilegedAddStaticNeighborOnDummy) {
    if (!hasNetAdmin()) {
        GTEST_SKIP() << "neighbor writes need CAP_NET_ADMIN "
                        "(try: unshare --user --map-root-user --net)";
    }
    constexpr const char *kIf = "tc8dummy0";
    if (!createDummyIface(kIf)) {
        GTEST_SKIP() << "could not create a dummy interface (no dummy driver?)";
    }
    // Delete the dummy at scope exit unconditionally — even if an assertion below
    // early-returns — so a direct real-root run never leaks tc8dummy0 (which would
    // also make the next run's NLM_F_EXCL create self-mask as a skip).
    ScopeExit cleanup([&] { deleteIface(kIf); });

    dut::LinuxSocketBackend be;
    const std::uint32_t ip_be = ::htonl(0x0A000002);  // 10.0.0.2
    const std::uint8_t mac[6] = {0x02, 0xAA, 0xBB, 0xCC, 0xDD, 0xEE};
    EXPECT_TRUE(be.addStaticNeighbor(kIf, ip_be, mac))
        << "RTM_NEWNEIGH with NUD_PERMANENT + NDA_LLADDR was rejected";
    EXPECT_TRUE(be.removeNeighbor(kIf, ip_be)) << "RTM_DELNEIGH of the static entry failed";
    EXPECT_TRUE(be.removeNeighbor(kIf, ip_be)) << "removeNeighbor should be idempotent";
}

}  // namespace
}  // namespace tc8
