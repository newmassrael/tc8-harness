// Hermetic integration test for the TC8 Upper Tester server core
// (tc8::ut::UpperTesterServer) driven over loopback with the injected POSIX
// adapters. The pre-refactor server could not run on plain loopback (it
// enumerated non-loopback interfaces in start()); the ports-and-adapters core
// takes its interface config as parameters, so the whole opcode surface — the
// handler-table dispatch, the derived capability bitmap + OpPing top, the TCP
// session lifecycle, and the UDP backends — is now exercisable without a netns.

#include <arpa/inet.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <unistd.h>

#include <atomic>
#include <chrono>
#include <cstdint>
#include <cstring>
#include <memory>
#include <string>
#include <thread>
#include <vector>

#include <gtest/gtest.h>

#include "tc8/posix_socket_backend.h"
#include "posix_stack_probe.h"
#include "tc8/upper_tester_protocol.h"
#include "upper_tester/ut_server.h"

namespace {

namespace ut = ::tc8::ut;
using ::tc8::dut::PosixSocketBackend;
using ::tc8::dut::PosixStackProbe;

constexpr std::uint16_t kUtPort = 30650;
constexpr std::uint16_t kDataPort = 20050;
constexpr std::uint32_t kLoopbackWire = 0x7F000001u;  // 127.0.0.1, wire order

void appendBe16(std::vector<std::uint8_t> &v, std::uint16_t x) {
    v.push_back(static_cast<std::uint8_t>(x >> 8));
    v.push_back(static_cast<std::uint8_t>(x & 0xFF));
}
void appendBe32(std::vector<std::uint8_t> &v, std::uint32_t x) {
    v.push_back(static_cast<std::uint8_t>(x >> 24));
    v.push_back(static_cast<std::uint8_t>((x >> 16) & 0xFF));
    v.push_back(static_cast<std::uint8_t>((x >> 8) & 0xFF));
    v.push_back(static_cast<std::uint8_t>(x & 0xFF));
}

// Send one UT request to loopback:`port` and return the full response frame
// (empty on timeout).
std::vector<std::uint8_t> udpRoundtrip(std::uint16_t port, std::uint8_t opcode,
                                       const std::vector<std::uint8_t> &params,
                                       std::uint8_t req_id = 0x42) {
    int fd = ::socket(AF_INET, SOCK_DGRAM, 0);
    EXPECT_GE(fd, 0);
    timeval tv{2, 0};
    ::setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
    std::vector<std::uint8_t> req{opcode, req_id};
    req.insert(req.end(), params.begin(), params.end());
    sockaddr_in dst{};
    dst.sin_family = AF_INET;
    dst.sin_port = ::htons(port);
    dst.sin_addr.s_addr = ::htonl(INADDR_LOOPBACK);
    ::sendto(fd, req.data(), req.size(), 0, reinterpret_cast<sockaddr *>(&dst), sizeof(dst));
    std::uint8_t buf[2048];
    const ssize_t n = ::recvfrom(fd, buf, sizeof(buf), 0, nullptr, nullptr);
    ::close(fd);
    if (n < 0) return {};
    return std::vector<std::uint8_t>(buf, buf + n);
}

int connectLoopbackTcp(std::uint16_t port) {
    int c = ::socket(AF_INET, SOCK_STREAM, 0);
    sockaddr_in d{};
    d.sin_family = AF_INET;
    d.sin_port = ::htons(port);
    d.sin_addr.s_addr = ::htonl(INADDR_LOOPBACK);
    if (::connect(c, reinterpret_cast<sockaddr *>(&d), sizeof(d)) != 0) {
        ::close(c);
        return -1;
    }
    return c;
}

int listenLoopbackTcp(std::uint16_t port) {
    int s = ::socket(AF_INET, SOCK_STREAM, 0);
    int on = 1;
    ::setsockopt(s, SOL_SOCKET, SO_REUSEADDR, &on, sizeof(on));
    sockaddr_in a{};
    a.sin_family = AF_INET;
    a.sin_port = ::htons(port);
    a.sin_addr.s_addr = ::htonl(INADDR_LOOPBACK);
    if (::bind(s, reinterpret_cast<sockaddr *>(&a), sizeof(a)) != 0 || ::listen(s, 1) != 0) {
        ::close(s);
        return -1;
    }
    return s;
}

void settle() { std::this_thread::sleep_for(std::chrono::milliseconds(150)); }

class UtServerTest : public ::testing::Test {
protected:
    void SetUp() override {
        server_ = std::make_unique<ut::UpperTesterServer>(std::make_unique<PosixSocketBackend>(),
                                                          std::make_unique<PosixStackProbe>());
        ASSERT_TRUE(server_->start(::htonl(INADDR_LOOPBACK), /*bcast=*/0, kUtPort, kDataPort));
    }
    void TearDown() override {
        if (server_) server_->stop();
    }
    std::vector<std::uint8_t> rt(std::uint8_t opcode, const std::vector<std::uint8_t> &params) {
        return udpRoundtrip(kUtPort, opcode, params);
    }
    std::unique_ptr<ut::UpperTesterServer> server_;
};

// ---- capability surface (derived from the handler table) --------------------

TEST_F(UtServerTest, PingReportsContiguousTop) {
    const auto r = rt(ut::OpPing, {});
    ASSERT_EQ(r.size(), 4u);
    EXPECT_EQ(r[0], ut::OpPing | ut::kResponseBit);
    EXPECT_EQ(r[1], 0x42);
    EXPECT_EQ(r[2], ut::kStatusOk);
    // The bare core registers 0x01..0x0B + 0x13..0x16; 0x0C..0x12 are
    // platform extensions, so the contiguous top is 0x0B.
    EXPECT_EQ(r[3], ut::OpReceiveTcpDataOob);
}

TEST_F(UtServerTest, QueryCapabilitiesMatchesTable) {
    const auto r = rt(ut::OpQueryCapabilities, {});
    ASSERT_GE(r.size(), 4u);
    EXPECT_EQ(r[2], ut::kStatusOk);
    const std::uint8_t len = r[3];
    ASSERT_EQ(r.size(), 4u + len);
    const std::uint8_t *bm = r.data() + 4;
    const std::uint8_t builtins[] = {
        ut::OpGetReceivedUdp,      ut::OpTriggerSendUdp,    ut::OpOpenTcpSocket,
        ut::OpCloseTcpSocket,      ut::OpQueryTcpEstablished, ut::OpSendTcpData,
        ut::OpReceiveTcpData,      ut::OpShutdownTcpSocketWr, ut::OpAbortTcpSocket,
        ut::OpSendTcpDataPattern,  ut::OpReceiveTcpDataOob,   ut::OpQueryTcpInfo,
        ut::OpCreateUdpReceivePorts, ut::OpPing,              ut::OpQueryCapabilities};
    for (std::uint8_t op : builtins) {
        EXPECT_TRUE(ut::capabilityBitSet(bm, len, op)) << "builtin opcode " << int(op);
    }
    const std::uint8_t extensions[] = {ut::OpStartLLAutoconf, ut::OpQueryDhcpLease,
                                       ut::OpConditionArpCache};
    for (std::uint8_t op : extensions) {
        EXPECT_FALSE(ut::capabilityBitSet(bm, len, op)) << "unregistered opcode " << int(op);
    }
}

TEST_F(UtServerTest, UnknownOpcodeRejected) {
    const auto r = rt(0x7E, {});
    ASSERT_EQ(r.size(), 3u);
    EXPECT_EQ(r[0], 0x7E | ut::kResponseBit);
    EXPECT_EQ(r[2], ut::kStatusUnknownOpcode);
}

TEST_F(UtServerTest, MalformedRequestRejected) {
    // OpGetReceivedUdp needs 6 param bytes; send 3.
    const auto r = rt(ut::OpGetReceivedUdp, {0x00, 0x00, 0x00});
    ASSERT_EQ(r.size(), 3u);
    EXPECT_EQ(r[2], ut::kStatusMalformed);
}

// ---- UDP backends -----------------------------------------------------------

TEST_F(UtServerTest, CreateUdpReceivePorts) {
    const auto r = rt(ut::OpCreateUdpReceivePorts, {3});
    ASSERT_EQ(r.size(), 4u);
    EXPECT_EQ(r[2], ut::kStatusOk);
    EXPECT_EQ(r[3], 3);
}

TEST_F(UtServerTest, GetReceivedUdpNotReceived) {
    std::vector<std::uint8_t> params;
    appendBe16(params, kDataPort);
    appendBe32(params, kLoopbackWire);
    const auto r = rt(ut::OpGetReceivedUdp, params);
    ASSERT_EQ(r.size(), 4u);
    EXPECT_EQ(r[2], ut::kStatusOk);
    EXPECT_EQ(r[3], 0x00);  // not received
}

TEST_F(UtServerTest, GetReceivedUdpRecordsDatagram) {
    int s = ::socket(AF_INET, SOCK_DGRAM, 0);
    sockaddr_in d{};
    d.sin_family = AF_INET;
    d.sin_port = ::htons(kDataPort);
    d.sin_addr.s_addr = ::htonl(INADDR_LOOPBACK);
    const char *msg = "ping";
    ::sendto(s, msg, 4, 0, reinterpret_cast<sockaddr *>(&d), sizeof(d));
    ::close(s);
    settle();

    std::vector<std::uint8_t> params;
    appendBe16(params, kDataPort);
    appendBe32(params, kLoopbackWire);
    const auto r = rt(ut::OpGetReceivedUdp, params);
    // status + received(1) + src_ip(4) + src_port(2) + payload_len(2) + payload(4)
    ASSERT_EQ(r.size(), 3u + 1 + 4 + 2 + 2 + 4);
    EXPECT_EQ(r[2], ut::kStatusOk);
    EXPECT_EQ(r[3], 0x01);
    const std::uint16_t plen = static_cast<std::uint16_t>((r[10] << 8) | r[11]);
    EXPECT_EQ(plen, 4u);
    EXPECT_EQ(std::string(r.begin() + 12, r.end()), "ping");
}

TEST_F(UtServerTest, TriggerSendUdpEmits) {
    int rx = ::socket(AF_INET, SOCK_DGRAM, 0);
    sockaddr_in a{};
    a.sin_family = AF_INET;
    a.sin_port = 0;  // ephemeral
    a.sin_addr.s_addr = ::htonl(INADDR_LOOPBACK);
    ASSERT_EQ(::bind(rx, reinterpret_cast<sockaddr *>(&a), sizeof(a)), 0);
    sockaddr_in bound{};
    socklen_t bl = sizeof(bound);
    ::getsockname(rx, reinterpret_cast<sockaddr *>(&bound), &bl);
    const std::uint16_t rp = ::ntohs(bound.sin_port);
    timeval tv{2, 0};
    ::setsockopt(rx, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));

    std::vector<std::uint8_t> params;
    appendBe16(params, 20061);          // src_port
    appendBe32(params, kLoopbackWire);  // dst_ip
    appendBe16(params, rp);             // dst_port
    appendBe16(params, 2);              // payload_len
    params.push_back('g');
    params.push_back('o');
    const auto r = rt(ut::OpTriggerSendUdp, params);
    ASSERT_EQ(r.size(), 3u);
    EXPECT_EQ(r[2], ut::kStatusOk);

    std::uint8_t buf[16];
    const ssize_t n = ::recvfrom(rx, buf, sizeof(buf), 0, nullptr, nullptr);
    ::close(rx);
    ASSERT_EQ(n, 2);
    EXPECT_EQ(std::string(buf, buf + 2), "go");
}

// ---- TCP session lifecycle --------------------------------------------------

TEST_F(UtServerTest, TcpPassiveSendReceiveClose) {
    constexpr std::uint16_t lp = 30751;
    auto open = rt(ut::OpOpenTcpSocket,
                   {ut::kSocketTypePassive, static_cast<std::uint8_t>(lp >> 8),
                    static_cast<std::uint8_t>(lp & 0xFF)});
    ASSERT_EQ(open.size(), 4u);
    ASSERT_EQ(open[2], ut::kStatusOk);
    const std::uint8_t sid = open[3];

    const int c = connectLoopbackTcp(lp);
    ASSERT_GE(c, 0);
    settle();

    auto est = rt(ut::OpQueryTcpEstablished, {sid});
    ASSERT_EQ(est.size(), 4u);
    EXPECT_EQ(est[2], ut::kStatusOk);
    EXPECT_EQ(est[3], 1);

    // DUT -> client
    auto snd = rt(ut::OpSendTcpData, {sid, 0x00, 0x05, 'h', 'e', 'l', 'l', 'o'});
    ASSERT_EQ(snd.size(), 3u);
    EXPECT_EQ(snd[2], ut::kStatusOk);
    std::uint8_t cb[16];
    const ssize_t cn = ::recv(c, cb, sizeof(cb), 0);
    ASSERT_EQ(cn, 5);
    EXPECT_EQ(std::string(cb, cb + 5), "hello");

    // client -> DUT
    ::send(c, "world", 5, 0);
    std::vector<std::uint8_t> rp{sid};
    appendBe16(rp, 5);     // expected_len
    appendBe16(rp, 1000);  // timeout_ms
    auto rcv = rt(ut::OpReceiveTcpData, rp);
    ASSERT_EQ(rcv.size(), 3u + 2u + 5u);
    EXPECT_EQ(rcv[2], ut::kStatusOk);
    const std::uint16_t rl = static_cast<std::uint16_t>((rcv[3] << 8) | rcv[4]);
    EXPECT_EQ(rl, 5u);
    EXPECT_EQ(std::string(rcv.begin() + 5, rcv.end()), "world");

    auto cl = rt(ut::OpCloseTcpSocket, {sid});
    ASSERT_EQ(cl.size(), 3u);
    EXPECT_EQ(cl[2], ut::kStatusOk);
    // socket id retired
    auto gone = rt(ut::OpQueryTcpEstablished, {sid});
    EXPECT_EQ(gone[2], ut::kStatusUnknownSocket);
    ::close(c);
}

TEST_F(UtServerTest, TcpQueryInfoEstablished) {
    constexpr std::uint16_t lp = 30752;
    auto open = rt(ut::OpOpenTcpSocket,
                   {ut::kSocketTypePassive, static_cast<std::uint8_t>(lp >> 8),
                    static_cast<std::uint8_t>(lp & 0xFF)});
    ASSERT_EQ(open[2], ut::kStatusOk);
    const std::uint8_t sid = open[3];
    const int c = connectLoopbackTcp(lp);
    ASSERT_GE(c, 0);
    settle();

    auto info = rt(ut::OpQueryTcpInfo, {sid});
    // status + state(1) + rto(4) + retransmits(1) + unacked(4)
    ASSERT_EQ(info.size(), 3u + 10u);
    EXPECT_EQ(info[2], ut::kStatusOk);
    EXPECT_EQ(info[3], ut::kTcpStateEstablished);
    rt(ut::OpCloseTcpSocket, {sid});
    ::close(c);
}

TEST_F(UtServerTest, TcpSendPatternAndShutdown) {
    constexpr std::uint16_t lp = 30753;
    auto open = rt(ut::OpOpenTcpSocket,
                   {ut::kSocketTypePassive, static_cast<std::uint8_t>(lp >> 8),
                    static_cast<std::uint8_t>(lp & 0xFF)});
    ASSERT_EQ(open[2], ut::kStatusOk);
    const std::uint8_t sid = open[3];
    const int c = connectLoopbackTcp(lp);
    ASSERT_GE(c, 0);
    settle();

    // pattern: 10 bytes of 0xAB
    auto pat = rt(ut::OpSendTcpDataPattern, {sid, 0xAB, 0x00, 0x0A});
    ASSERT_EQ(pat.size(), 3u);
    EXPECT_EQ(pat[2], ut::kStatusOk);
    std::uint8_t cb[32];
    ssize_t got = 0;
    while (got < 10) {
        const ssize_t k = ::recv(c, cb + got, sizeof(cb) - got, 0);
        if (k <= 0) break;
        got += k;
    }
    ASSERT_EQ(got, 10);
    for (int i = 0; i < 10; ++i) EXPECT_EQ(cb[i], 0xABu);

    // SHUT_WR -> client sees EOF
    auto sh = rt(ut::OpShutdownTcpSocketWr, {sid});
    ASSERT_EQ(sh.size(), 3u);
    EXPECT_EQ(sh[2], ut::kStatusOk);
    std::uint8_t eofbuf[4];
    EXPECT_EQ(::recv(c, eofbuf, sizeof(eofbuf), 0), 0);  // peer FIN
    rt(ut::OpCloseTcpSocket, {sid});
    ::close(c);
}

TEST_F(UtServerTest, TcpReceiveOobEmptyOnNoUrgent) {
    constexpr std::uint16_t lp = 30754;
    auto open = rt(ut::OpOpenTcpSocket,
                   {ut::kSocketTypePassive, static_cast<std::uint8_t>(lp >> 8),
                    static_cast<std::uint8_t>(lp & 0xFF)});
    ASSERT_EQ(open[2], ut::kStatusOk);
    const std::uint8_t sid = open[3];
    const int c = connectLoopbackTcp(lp);
    ASSERT_GE(c, 0);
    settle();

    std::vector<std::uint8_t> rp{sid};
    appendBe16(rp, 1);    // expected_len
    appendBe16(rp, 200);  // timeout_ms (no urgent data -> empty)
    auto oob = rt(ut::OpReceiveTcpDataOob, rp);
    ASSERT_EQ(oob.size(), 3u + 2u);  // status + received_len(0), no bytes
    EXPECT_EQ(oob[2], ut::kStatusOk);
    EXPECT_EQ((oob[3] << 8) | oob[4], 0);
    rt(ut::OpCloseTcpSocket, {sid});
    ::close(c);
}

TEST_F(UtServerTest, TcpActiveConnectAndAbort) {
    constexpr std::uint16_t remote_port = 30755;
    constexpr std::uint16_t local_port = 30756;
    const int ls = listenLoopbackTcp(remote_port);
    ASSERT_GE(ls, 0);

    std::vector<std::uint8_t> params{ut::kSocketTypeActive};
    appendBe16(params, local_port);
    appendBe32(params, kLoopbackWire);
    appendBe16(params, remote_port);
    auto open = rt(ut::OpOpenTcpSocket, params);
    ASSERT_EQ(open.size(), 4u);
    ASSERT_EQ(open[2], ut::kStatusOk);
    const std::uint8_t sid = open[3];

    const int conn = ::accept(ls, nullptr, nullptr);
    ASSERT_GE(conn, 0);
    settle();

    auto est = rt(ut::OpQueryTcpEstablished, {sid});
    ASSERT_EQ(est.size(), 4u);
    EXPECT_EQ(est[3], 1);

    auto ab = rt(ut::OpAbortTcpSocket, {sid});
    ASSERT_EQ(ab.size(), 3u);
    EXPECT_EQ(ab[2], ut::kStatusOk);
    auto gone = rt(ut::OpAbortTcpSocket, {sid});
    EXPECT_EQ(gone[2], ut::kStatusUnknownSocket);  // already torn down

    ::close(conn);
    ::close(ls);
}

// ---- extension registration (platform-specific opcode families) -------------

TEST(UtServerExtensionTest, RegisteredOpcodeDispatchesAndAdvertises) {
    ut::UpperTesterServer server(std::make_unique<PosixSocketBackend>(),
                                 std::make_unique<PosixStackProbe>());
    // Atomic: the handler runs on the server thread, the assertion on the main
    // thread; UDP send/recv is not a happens-before TSan recognises.
    std::atomic<bool> called{false};
    // 0x0C is normally a platform extension (LL autoconf). Register a stub so the
    // contiguous block becomes 0x01..0x0C and the bitmap gains the bit.
    server.registerOpcode(ut::OpStartLLAutoconf,
                          [&](const std::uint8_t *, std::size_t, std::uint8_t &st,
                              std::vector<std::uint8_t> &body) {
                              called.store(true);
                              body.push_back(0xCD);
                              st = ut::kStatusOk;
                          });
    constexpr std::uint16_t kPort = 30660;
    ASSERT_TRUE(server.start(::htonl(INADDR_LOOPBACK), 0, kPort, 20060));

    auto ping = udpRoundtrip(kPort, ut::OpPing, {});
    ASSERT_EQ(ping.size(), 4u);
    EXPECT_EQ(ping[3], ut::OpStartLLAutoconf);  // contiguous top now 0x0C

    auto disp = udpRoundtrip(kPort, ut::OpStartLLAutoconf, {});
    ASSERT_EQ(disp.size(), 4u);
    EXPECT_EQ(disp[2], ut::kStatusOk);
    EXPECT_EQ(disp[3], 0xCDu);
    EXPECT_TRUE(called.load());

    auto caps = udpRoundtrip(kPort, ut::OpQueryCapabilities, {});
    ASSERT_GE(caps.size(), 4u);
    EXPECT_TRUE(ut::capabilityBitSet(caps.data() + 4, caps[3], ut::OpStartLLAutoconf));

    server.stop();
}

}  // namespace
