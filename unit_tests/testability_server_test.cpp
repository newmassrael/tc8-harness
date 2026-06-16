#include <arpa/inet.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <unistd.h>

#include <cerrno>
#include <chrono>
#include <cstdint>
#include <cstring>
#include <thread>
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

    const auto sock = stimulus::testabilityCreateAndBind(cfg, tp::kGidTcp, false, 0xFFFF, 0);
    ASSERT_TRUE(sock.has_value());
    ASSERT_TRUE(stimulus::testabilityTcpConnect(cfg, *sock, ntohs(la.sin_port),
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
    const auto res = stimulus::testabilityReceiveAndForward(
        cfg, *sock, /*max_fwd=*/16, /*max_len=*/static_cast<std::uint16_t>(body.size()),
        [&] { ::send(afd, body.data(), body.size(), 0); });

    EXPECT_TRUE(res.ok);
    EXPECT_EQ(res.drop_cnt, pre.size());
    EXPECT_EQ(res.full_len, body.size());
    EXPECT_EQ(res.payload, body);

    ::close(afd);
    ::close(lfd);
    EXPECT_TRUE(stimulus::testabilityCloseSocket(cfg, tp::kGidTcp, *sock).eok());
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

    const auto sock = stimulus::testabilityCreateAndBind(cfg, tp::kGidTcp, false, 0xFFFF, 0);
    ASSERT_TRUE(sock.has_value());
    ASSERT_TRUE(stimulus::testabilityTcpConnect(cfg, *sock, ntohs(la.sin_port),
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
    const auto res = stimulus::testabilityReceiveAndForward(
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
    EXPECT_TRUE(stimulus::testabilityCloseSocket(cfg, tp::kGidTcp, *sock).eok());
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
    constexpr std::uint16_t kDutUdpPort = 39733;
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

    constexpr std::uint16_t kLocalBindPort = 39822;
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

    constexpr std::uint16_t kListenPort = 39813;
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
        stimulus::testabilityCreateAndBind(cfg, tp::kGidUdp, /*do_bind=*/true, 0xFFFF, 0);
    ASSERT_TRUE(sock.has_value());

    constexpr std::uint8_t kTtl = 7;
    std::vector<std::uint8_t> cs;
    tp::appendU16(cs, *sock);        // socketId
    tp::appendU16(cs, tp::kCfgTtl);  // paramId 0x0000
    const std::uint8_t ttl_val = kTtl;
    tp::appendVint8(cs, &ttl_val, 1);  // paramVal (1 byte)
    EXPECT_TRUE(stimulus::testabilityCall(cfg, tp::kGidUdp, tp::kPidConfigureSocket, cs).eok());

    std::vector<std::uint8_t> sd;
    tp::appendU16(sd, *sock);                          // socketId
    tp::appendU16(sd, 3);                              // totalLen
    tp::appendU16(sd, ntohs(ra.sin_port));             // destPort
    tp::appendIpv4Addr(sd, ::htonl(INADDR_LOOPBACK));  // destAddr
    const std::vector<std::uint8_t> body = {'T', 'T', 'L'};
    tp::appendVint8(sd, body.data(), body.size());  // data
    EXPECT_TRUE(stimulus::testabilityCall(cfg, tp::kGidUdp, tp::kPidSendData, sd).eok());

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

    EXPECT_TRUE(stimulus::testabilityCloseSocket(cfg, tp::kGidUdp, *sock).eok());
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
        EXPECT_EQ(stimulus::testabilityCall(cfg, tp::kGidUdp, tp::kPidConfigureSocket, cs).rid,
                  tp::kRidEIsd);
    }

    const auto sock = stimulus::testabilityCreateAndBind(cfg, tp::kGidTcp, false, 0xFFFF, 0);
    ASSERT_TRUE(sock.has_value());

    // Truncated: socketId only, no paramId / paramVal.
    {
        std::vector<std::uint8_t> cs;
        tp::appendU16(cs, *sock);
        EXPECT_EQ(stimulus::testabilityCall(cfg, tp::kGidTcp, tp::kPidConfigureSocket, cs).rid,
                  tp::kRidEInv);
    }

    // Unknown paramId on a valid socket.
    {
        std::vector<std::uint8_t> cs;
        tp::appendU16(cs, *sock);
        tp::appendU16(cs, 0x00FF);  // not a defined selector
        const std::uint8_t v = 1;
        tp::appendVint8(cs, &v, 1);
        EXPECT_EQ(stimulus::testabilityCall(cfg, tp::kGidTcp, tp::kPidConfigureSocket, cs).rid,
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
            stimulus::testabilityCall(cfg, tp::kGidTcp, tp::kPidConfigureSocket, cs).eok());
    }

    EXPECT_TRUE(stimulus::testabilityCloseSocket(cfg, tp::kGidTcp, *sock).eok());
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

// ── ICMP group (GID 0x03): ECHO_REQUEST (PRS_TPSP §6.10) ──

// ECHO_REQUEST to loopback emits and reports E_OK. ping_group_range is open on
// CI / dev hosts, so the unprivileged SOCK_DGRAM/IPPROTO_ICMP path applies (the
// server falls back to SOCK_RAW only where ping sockets are restricted).
TEST_F(TestabilityServerTest, IcmpEchoRequestToLoopbackReturnsEOk) {
    const auto cfg = loopbackConfig();
    const std::vector<std::uint8_t> payload = {'p', 'i', 'n', 'g'};
    const auto r =
        stimulus::testabilityEchoRequest(cfg, /*iface=*/"", ::htonl(INADDR_LOOPBACK), payload);
    EXPECT_TRUE(r.eok()) << "ECHO_REQUEST to loopback should emit and report E_OK (rid="
                         << static_cast<int>(r.rid) << ")";
}

// An empty payload is valid (data vint8 n=0): a bare Echo Request still emits.
TEST_F(TestabilityServerTest, IcmpEchoRequestEmptyPayloadReturnsEOk) {
    const auto cfg = loopbackConfig();
    const auto r = stimulus::testabilityEchoRequest(cfg, /*iface=*/"", ::htonl(INADDR_LOOPBACK), {});
    EXPECT_TRUE(r.eok()) << "rid=" << static_cast<int>(r.rid);
}

// An unknown interface name maps to the spec's E_IIF (PRS_TPSP §6.8). Relies on
// unprivileged SO_BINDTODEVICE returning ENODEV (Linux >= 5.7).
TEST_F(TestabilityServerTest, IcmpEchoRequestInvalidInterfaceReturnsEIif) {
    const auto cfg = loopbackConfig();
    const auto r = stimulus::testabilityEchoRequest(cfg, /*iface=*/"tc8-no-such-if",
                                                    ::htonl(INADDR_LOOPBACK), {});
    EXPECT_TRUE(r.ok);  // the SP itself round-tripped
    EXPECT_EQ(r.rid, tp::kRidEIif) << "unknown interface should map to E_IIF";
}

// ── PRS_TPSP §6.6 OEM extension / override seam (registerPrimitive) ──

// EXTEND: a registered handler for a non-standard group the core knows nothing
// about (GID 0x7F, counted down per PRS_TPSP §6.6) is dispatched with the parsed
// request and its DAT, and its Result ID + response DAT reach the caller.
TEST(TestabilityServerSeamTest, OemHandlerExtendsNonStandardGroup) {
    constexpr std::uint16_t kPort = 39711;
    constexpr std::uint8_t kVendorGid = 0x7F;
    constexpr std::uint8_t kVendorPid = 0x2A;

    dut::TestabilityServer server;
    server.registerPrimitive(
        kVendorGid, kVendorPid,
        [](const tp::Header &, const std::uint8_t *dat, std::size_t dat_len, const sockaddr_in &,
           std::uint8_t &rid, std::vector<std::uint8_t> &resp) {
            resp.push_back(0xA5);  // tag proving the handler ran
            resp.insert(resp.end(), dat, dat + dat_len);  // echo the request DAT back
            rid = tp::kRidEOk;
        });
    ASSERT_TRUE(server.start(kPort));

    stimulus::TestabilityConfig cfg;
    cfg.dut_ip_be = ::htonl(INADDR_LOOPBACK);
    cfg.dut_port = kPort;
    const std::vector<std::uint8_t> req = {0x01, 0x02, 0x03};
    const auto r = stimulus::testabilityCall(cfg, kVendorGid, kVendorPid, req);
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
    constexpr std::uint16_t kPort = 39712;

    dut::TestabilityServer server;
    server.registerPrimitive(
        tp::kGidGeneral, tp::kPidGetVersion,
        [](const tp::Header &, const std::uint8_t *, std::size_t, const sockaddr_in &,
           std::uint8_t &rid, std::vector<std::uint8_t> &resp) {
            tp::appendU16(resp, 9);  // a version the built-in never reports (1.2.0)
            tp::appendU16(resp, 9);
            tp::appendU16(resp, 9);
            rid = tp::kRidEOk;
        });
    ASSERT_TRUE(server.start(kPort));

    stimulus::TestabilityConfig cfg;
    cfg.dut_ip_be = ::htonl(INADDR_LOOPBACK);
    cfg.dut_port = kPort;
    const auto v = stimulus::testabilityGetVersion(cfg);
    server.stop();

    ASSERT_TRUE(v.has_value());
    EXPECT_EQ(v->major, 9u);  // the vendor override, not kVersionMajor
    EXPECT_EQ(v->minor, 9u);
    EXPECT_EQ(v->patch, 9u);
}

}  // namespace
}  // namespace tc8
