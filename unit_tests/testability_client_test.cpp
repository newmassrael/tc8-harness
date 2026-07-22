#include <arpa/inet.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <unistd.h>

#include <atomic>
#include <cstdint>
#include <cstring>
#include <mutex>
#include <thread>
#include <vector>

#include <gtest/gtest.h>

#include "dissect/someip_header.h"
#include "tc8/testability_client.h"
#include "tc8/testability_protocol.h"

namespace tc8::testability {
namespace {

namespace tp = ::tc8::testability;

// ── PRS_TPSP §6.1 Method ID composition (the one place GID/PID/EVB pack/unpack) ──

TEST(TestabilityProtocol, MethodIdEncodesGidPid) {
    // GENERAL (0x00) / START_TEST (0x02) => method_id 0x0002.
    EXPECT_EQ(tp::methodId(tp::kGidGeneral, tp::kPidStartTest), 0x0002u);
    // UDP (0x01) / SEND_DATA (0x02) => (GID<<8)|PID = 0x0102.
    EXPECT_EQ(tp::methodId(tp::kGidUdp, tp::kPidSendData), 0x0102u);
    // PHY (0x0C) / SET_PHY_TX_MODE (0x03) => 0x0C03.
    EXPECT_EQ(tp::methodId(tp::kGidPhy, 0x03), 0x0C03u);
    // Event bit sets the top bit of the method-id half.
    EXPECT_EQ(tp::methodId(tp::kGidUdp, tp::kPidReceiveAndForward, /*event=*/true),
              0x8103u);
}

TEST(TestabilityProtocol, MethodIdDecodesRoundTrip) {
    const std::uint16_t mid = tp::methodId(tp::kGidTcp, tp::kPidConnect);
    EXPECT_EQ(tp::gidOf(mid), tp::kGidTcp);
    EXPECT_EQ(tp::pidOf(mid), tp::kPidConnect);
    EXPECT_FALSE(tp::isEvent(mid));
    EXPECT_TRUE(tp::isEvent(tp::methodId(tp::kGidUdp, tp::kPidReceiveAndForward, true)));
}

// ── PRS_TPSP §6.1 message layout ──

TEST(TestabilityProtocol, StartTestRequestLayout) {
    tp::Header h;
    h.service_id = tp::kDefaultServiceId;  // 0x0105
    h.method_id = tp::methodId(tp::kGidGeneral, tp::kPidStartTest);
    h.tid = tp::kTidRequest;
    const auto msg = tp::buildMessage(h);  // no DAT

    ASSERT_EQ(msg.size(), tp::kHeaderSize);  // 16, no parameters
    EXPECT_EQ(msg[0], 0x01u);                // SID hi
    EXPECT_EQ(msg[1], 0x05u);                // SID lo
    EXPECT_EQ(msg[2], 0x00u);                // method hi (EVB|GID)
    EXPECT_EQ(msg[3], 0x02u);                // method lo (PID = START_TEST)
    // Length = 8 (no payload), BE32.
    EXPECT_EQ(msg[4], 0x00u);
    EXPECT_EQ(msg[5], 0x00u);
    EXPECT_EQ(msg[6], 0x00u);
    EXPECT_EQ(msg[7], 0x08u);
    EXPECT_EQ(msg[12], tp::kProtocolVersion);   // 0x01
    EXPECT_EQ(msg[13], tp::kInterfaceVersion);  // 0x01
    EXPECT_EQ(msg[14], tp::kTidRequest);        // 0x00
    EXPECT_EQ(msg[15], tp::kRidEOk);            // 0x00
}

// The shared testability codec must emit valid SOME/IP — cross-check its
// output against the harness's INDEPENDENT SOME/IP parser so a layout change
// on either side is caught (the two are never edited together).
TEST(TestabilityProtocol, BuildMessageIsValidSomeIp) {
    const std::uint8_t dat[3] = {0xAA, 0xBB, 0xCC};
    tp::Header h;
    h.method_id = tp::methodId(tp::kGidUdp, tp::kPidSendData);
    const auto msg = tp::buildMessage(h, dat, sizeof(dat));

    const auto parsed = dissect::parseSomeIpHeader(msg.data(), msg.size());
    ASSERT_TRUE(parsed.has_value());
    EXPECT_EQ(parsed->header.service_id, tp::kDefaultServiceId);
    EXPECT_EQ(parsed->header.method_id, 0x0102u);
    EXPECT_EQ(parsed->header.length, 8u + sizeof(dat));
    EXPECT_EQ(parsed->header.protocol_version, 0x01u);
    EXPECT_EQ(parsed->header.interface_version, 0x01u);
    EXPECT_EQ(parsed->header.message_type, someip::MessageType::REQUEST);
    EXPECT_EQ(parsed->header.return_code, someip::ReturnCode::E_OK);
}

TEST(TestabilityProtocol, BuildParseRoundTrip) {
    tp::Header h;
    h.service_id = 0x0105;
    h.method_id = tp::methodId(tp::kGidTcp, tp::kPidConnect);
    h.tid = tp::kTidResponse;
    h.rid = tp::kRidEIsd;  // a testability-specific RID outside SOME/IP's range
    const std::uint8_t dat[2] = {0x12, 0x34};
    const auto msg = tp::buildMessage(h, dat, sizeof(dat));

    const auto got = tp::parseHeader(msg.data(), msg.size());
    ASSERT_TRUE(got.has_value());
    EXPECT_EQ(got->service_id, 0x0105u);
    EXPECT_EQ(got->method_id, tp::methodId(tp::kGidTcp, tp::kPidConnect));
    EXPECT_EQ(got->length, 10u);
    EXPECT_EQ(got->tid, tp::kTidResponse);
    EXPECT_EQ(got->rid, tp::kRidEIsd);
}

TEST(TestabilityProtocol, ParseHeaderRejectsShort) {
    const std::uint8_t buf[8] = {};
    EXPECT_FALSE(tp::parseHeader(buf, sizeof(buf)).has_value());
}

// ── PRS_TPSP §6.7.5.2 text parameter (END_TEST tsName) ──

TEST(TestabilityParams, TextHasBomAndNull) {
    std::vector<std::uint8_t> dat;
    tp::appendText(dat, "ATS");  // 3 ASCII chars
    // vint8 n = BOM(3) + "ATS"(3) + null(1) = 7.
    ASSERT_EQ(dat.size(), 2u + 7u);
    EXPECT_EQ(dat[0], 0x00u);
    EXPECT_EQ(dat[1], 0x07u);
    EXPECT_EQ(dat[2], 0xEFu);  // BOM
    EXPECT_EQ(dat[3], 0xBBu);
    EXPECT_EQ(dat[4], 0xBFu);
    EXPECT_EQ(dat[5], 'A');
    EXPECT_EQ(dat[6], 'T');
    EXPECT_EQ(dat[7], 'S');
    EXPECT_EQ(dat[8], 0x00u);  // null terminator
}

TEST(TestabilityParams, EmptyTextIsZeroLength) {
    std::vector<std::uint8_t> dat;
    tp::appendText(dat, "");
    ASSERT_EQ(dat.size(), 2u);
    EXPECT_EQ(dat[0], 0x00u);
    EXPECT_EQ(dat[1], 0x00u);
}

// ── PRS_TPSP §6.7.5.2 text decode (readText — the appendText inverse) ──

TEST(TestabilityParams, ReadTextRoundTripsAppendText) {
    std::vector<std::uint8_t> dat;
    tp::appendText(dat, "eth1.5");
    std::size_t off = 0;
    std::string out;
    ASSERT_TRUE(tp::readText(dat.data(), dat.size(), off, out));
    EXPECT_EQ(out, "eth1.5");    // BOM + null stripped
    EXPECT_EQ(off, dat.size());  // consumed the whole field, ready for the next param
}

TEST(TestabilityParams, ReadTextEmptyIsEmptyString) {
    std::vector<std::uint8_t> dat;
    tp::appendText(dat, "");
    std::size_t off = 0;
    std::string out = "sentinel";
    ASSERT_TRUE(tp::readText(dat.data(), dat.size(), off, out));
    EXPECT_TRUE(out.empty());
    EXPECT_EQ(off, 2u);  // just the vint8 length prefix
}

TEST(TestabilityParams, ReadTextToleratesBareString) {
    // A third-party client may send a vint8 of raw bytes with no BOM/null;
    // readText returns them verbatim (Postel's law).
    const std::uint8_t bare[] = {0x00, 0x03, 'e', 't', 'h'};
    std::size_t off = 0;
    std::string out;
    ASSERT_TRUE(tp::readText(bare, sizeof(bare), off, out));
    EXPECT_EQ(out, "eth");
}

TEST(TestabilityParams, ReadTextRejectsTruncatedField) {
    // vint8 claims 4 bytes but only 1 follows -> the field runs past the buffer.
    const std::uint8_t bad[] = {0x00, 0x04, 0xEF};
    std::size_t off = 0;
    std::string out;
    EXPECT_FALSE(tp::readText(bad, sizeof(bad), off, out));
}

TEST(TestabilityParams, Ipv4AddrIsVint8N4) {
    std::vector<std::uint8_t> dat;
    // 172.16.0.1 -> s_addr NBO; wire bytes must be AC 10 00 01.
    tp::appendIpv4Addr(dat, ::htonl(0xAC100001));
    ASSERT_EQ(dat.size(), 2u + 4u);
    EXPECT_EQ(dat[0], 0x00u);  // n hi
    EXPECT_EQ(dat[1], 0x04u);  // n lo = 4
    EXPECT_EQ(dat[2], 0xACu);
    EXPECT_EQ(dat[3], 0x10u);
    EXPECT_EQ(dat[4], 0x00u);
    EXPECT_EQ(dat[5], 0x01u);
}

TEST(TestabilityParams, Vint8RoundTripAndBounds) {
    std::vector<std::uint8_t> dat;
    const std::uint8_t body[3] = {0xDE, 0xAD, 0xBE};
    tp::appendVint8(dat, body, sizeof(body));

    std::size_t off = 0;
    const std::uint8_t *out = nullptr;
    std::uint16_t out_len = 0;
    ASSERT_TRUE(tp::readVint8(dat.data(), dat.size(), off, out, out_len));
    EXPECT_EQ(out_len, 3u);
    EXPECT_EQ(off, dat.size());
    EXPECT_EQ(std::memcmp(out, body, 3), 0);

    // A length prefix that overruns the buffer must be rejected, not over-read.
    const std::uint8_t truncated[3] = {0x00, 0x09, 0x01};  // claims 9, has 1
    std::size_t toff = 0;
    EXPECT_FALSE(tp::readVint8(truncated, sizeof(truncated), toff, out, out_len));
}

// appendU32/readU32 are the uint32 PRS_TPSP §6.7 scalar pair (EthTP carries
// ConnectionID / MessageID as uint32). Big-endian round trip through the SSOT,
// the 32-bit counterpart of the appendU16/readU16 path.
TEST(TestabilityParams, U32RoundTrip) {
    std::vector<std::uint8_t> dat;
    tp::appendU32(dat, 0x01020304u);
    ASSERT_EQ(dat.size(), 4u);
    EXPECT_EQ(dat[0], 0x01u);  // big-endian: most significant byte first
    EXPECT_EQ(dat[3], 0x04u);
    EXPECT_EQ(tp::readU32(dat.data()), 0x01020304u);
}

// ── Hermetic socket round trip: a loopback SOME/IP echo responder ──

// Minimal in-process testability responder: bind a UDP socket on 127.0.0.1,
// then for each request reply with a Response (TID 0x80, E_OK) echoing the
// service/method, with version DAT for GET_VERSION and a fixed socketId for
// CREATE_AND_BIND. Captures the last request's raw bytes so a test can assert
// the wrapper's wire encoding. Returns the bound port.
class LoopbackResponder {
public:
    // The socketId returned for any CREATE_AND_BIND (UDP or TCP).
    static constexpr std::uint16_t kSocketId = 0x0042;
    // Fabricated accept-Event fields emitted after a LISTEN_AND_ACCEPT request.
    static constexpr std::uint16_t kAcceptNewSocketId = 0x0099;
    static constexpr std::uint16_t kAcceptClientPort = 0x1234;
    LoopbackResponder() {
        fd_ = ::socket(AF_INET, SOCK_DGRAM, 0);
        sockaddr_in addr{};
        addr.sin_family = AF_INET;
        addr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
        addr.sin_port = 0;  // kernel picks a free port
        ::bind(fd_, reinterpret_cast<sockaddr *>(&addr), sizeof(addr));
        socklen_t len = sizeof(addr);
        ::getsockname(fd_, reinterpret_cast<sockaddr *>(&addr), &len);
        port_ = ntohs(addr.sin_port);
        thread_ = std::thread([this] { serve(); });
    }
    ~LoopbackResponder() {
        stop_ = true;
        ::shutdown(fd_, SHUT_RDWR);  // unblock the serve() recvfrom
        if (thread_.joinable()) {
            thread_.join();  // serve() has stopped touching fd_ before we close it
        }
        ::close(fd_);
    }
    std::uint16_t port() const { return port_; }

    // The DAT (parameter bytes after the 16-byte header) of the last request.
    std::vector<std::uint8_t> lastRequestDat() {
        std::lock_guard<std::mutex> lk(mu_);
        return last_req_dat_;
    }

private:
    void serve() {
        std::uint8_t buf[1500];
        while (!stop_) {
            sockaddr_in peer{};
            socklen_t plen = sizeof(peer);
            const ssize_t n = ::recvfrom(fd_, buf, sizeof(buf), 0,
                                         reinterpret_cast<sockaddr *>(&peer), &plen);
            if (n < static_cast<ssize_t>(tp::kHeaderSize)) {
                if (stop_) break;
                continue;
            }
            const auto req = tp::parseHeader(buf, static_cast<std::size_t>(n));
            if (!req) continue;

            {
                std::lock_guard<std::mutex> lk(mu_);
                last_req_dat_.assign(buf + tp::kHeaderSize, buf + n);
            }

            tp::Header resp = *req;
            resp.tid = tp::kTidResponse;
            resp.rid = tp::kRidEOk;
            std::vector<std::uint8_t> dat;
            const std::uint8_t gid = tp::gidOf(req->method_id);
            const std::uint8_t pid = tp::pidOf(req->method_id);
            if (gid == tp::kGidGeneral && pid == tp::kPidGetVersion) {
                const std::uint16_t v[3] = {tp::kVersionMajor, tp::kVersionMinor,
                                            tp::kVersionPatch};
                for (std::uint16_t x : v) {
                    dat.push_back(static_cast<std::uint8_t>(x >> 8));
                    dat.push_back(static_cast<std::uint8_t>(x & 0xFF));
                }
            } else if ((gid == tp::kGidUdp || gid == tp::kGidTcp) &&
                       pid == tp::kPidCreateAndBind) {
                dat.push_back(static_cast<std::uint8_t>(kSocketId >> 8));
                dat.push_back(static_cast<std::uint8_t>(kSocketId & 0xFF));
            }
            const auto out = tp::buildMessage(resp, dat.empty() ? nullptr : dat.data(),
                                              dat.size());
            ::sendto(fd_, out.data(), out.size(), 0, reinterpret_cast<sockaddr *>(&peer),
                     plen);

            // LISTEN_AND_ACCEPT: after the E_OK response, emit one fabricated
            // accept Event (TID 0x02 / EVB set) so the client wrapper's
            // event-await path is exercised. listenSocketId is echoed from the
            // request DAT (first u16).
            if (gid == tp::kGidTcp && pid == tp::kPidListenAndAccept &&
                static_cast<std::size_t>(n) >= tp::kHeaderSize + 2) {
                const std::uint16_t lsid = tp::readU16(buf + tp::kHeaderSize);
                tp::Header eh = *req;
                eh.method_id =
                    tp::methodId(tp::kGidTcp, tp::kPidListenAndAccept, /*event=*/true);
                eh.tid = tp::kTidEvent;
                eh.rid = tp::kRidEOk;
                std::vector<std::uint8_t> edat;
                tp::appendU16(edat, lsid);
                tp::appendU16(edat, kAcceptNewSocketId);
                tp::appendU16(edat, kAcceptClientPort);
                tp::appendIpv4Addr(edat, ::htonl(INADDR_LOOPBACK));
                const auto evout = tp::buildMessage(eh, edat.data(), edat.size());
                ::sendto(fd_, evout.data(), evout.size(), 0,
                         reinterpret_cast<sockaddr *>(&peer), plen);
            }
        }
    }

    int fd_ = -1;
    std::uint16_t port_ = 0;
    std::thread thread_;
    std::atomic<bool> stop_{false};
    std::mutex mu_;
    std::vector<std::uint8_t> last_req_dat_;
};

TestabilityConfig loopbackConfig(std::uint16_t port) {
    TestabilityConfig cfg;
    cfg.dut_ip_be = htonl(INADDR_LOOPBACK);
    cfg.dut_port = port;
    return cfg;
}

TEST(TestabilityClient, StartTestRoundTrip) {
    LoopbackResponder server;
    const auto r = testabilityStartTest(loopbackConfig(server.port()), /*timeout_ms=*/1000);
    EXPECT_TRUE(r.ok);
    EXPECT_EQ(r.tid, tp::kTidResponse);
    EXPECT_TRUE(r.eok());
}

TEST(TestabilityClient, GetVersionRoundTrip) {
    LoopbackResponder server;
    const auto v = testabilityGetVersion(loopbackConfig(server.port()), /*timeout_ms=*/1000);
    ASSERT_TRUE(v.has_value());
    EXPECT_EQ(v->major, tp::kVersionMajor);
    EXPECT_EQ(v->minor, tp::kVersionMinor);
    EXPECT_EQ(v->patch, tp::kVersionPatch);
}

TEST(TestabilityClient, CallTimesOutWithNoServer) {
    // Nothing listening on this loopback port — recv must time out, ok=false.
    TestabilityConfig cfg;
    cfg.dut_ip_be = htonl(INADDR_LOOPBACK);
    cfg.dut_port = 1;  // privileged, nothing bound in the test netns
    const auto r = testabilityCall(cfg, tp::kGidGeneral, tp::kPidStartTest, {},
                                   /*timeout_ms=*/150);
    EXPECT_FALSE(r.ok);
}

// ── PRS_TPSP §6.10 TCP group typed wrappers: return value + wire encoding ──

TEST(TestabilityClient, TcpCreateAndBindReturnsSocketIdAndEncodesRequest) {
    LoopbackResponder server;
    const auto sock = testabilityCreateAndBind(loopbackConfig(server.port()), tp::kGidTcp,
                                               /*do_bind=*/false, /*local_port=*/0xFFFF,
                                               /*local_addr_be=*/0, /*timeout_ms=*/1000);
    ASSERT_TRUE(sock.has_value());
    EXPECT_EQ(*sock, LoopbackResponder::kSocketId);

    // Request DAT: doBind(0) + localPort(0xFFFF) + localAddr ipxaddr(n=4, 0.0.0.0).
    const auto dat = server.lastRequestDat();
    ASSERT_EQ(dat.size(), 1u + 2u + 2u + 4u);
    EXPECT_EQ(dat[0], 0x00u);              // doBind = false
    EXPECT_EQ(dat[1], 0xFFu);              // localPort hi
    EXPECT_EQ(dat[2], 0xFFu);              // localPort lo (PORT_ANY)
    EXPECT_EQ(dat[3], 0x00u);              // ipxaddr n hi
    EXPECT_EQ(dat[4], 0x04u);              // ipxaddr n lo = 4
    EXPECT_EQ(dat[5], 0x00u);              // 0.0.0.0
    EXPECT_EQ(dat[8], 0x00u);
}

TEST(TestabilityClient, TcpConnectEncodesSocketDestPortAddr) {
    LoopbackResponder server;
    const auto r = testabilityTcpConnect(loopbackConfig(server.port()), /*socket_id=*/0x0042,
                                         /*dest_port=*/0x1F40, ::htonl(0xAC100001),
                                         /*timeout_ms=*/1000);
    EXPECT_TRUE(r.eok());

    // Request DAT: socketId(u16) + destPort(u16) + destAddr ipxaddr(n=4, AC 10 00 01).
    const auto dat = server.lastRequestDat();
    ASSERT_EQ(dat.size(), 2u + 2u + 2u + 4u);
    EXPECT_EQ(dat[0], 0x00u);  // socketId hi
    EXPECT_EQ(dat[1], 0x42u);  // socketId lo
    EXPECT_EQ(dat[2], 0x1Fu);  // destPort hi
    EXPECT_EQ(dat[3], 0x40u);  // destPort lo (8000)
    EXPECT_EQ(dat[4], 0x00u);  // ipxaddr n hi
    EXPECT_EQ(dat[5], 0x04u);  // ipxaddr n lo
    EXPECT_EQ(dat[6], 0xACu);  // 172.16.0.1
    EXPECT_EQ(dat[7], 0x10u);
    EXPECT_EQ(dat[8], 0x00u);
    EXPECT_EQ(dat[9], 0x01u);
}

TEST(TestabilityClient, TcpSendDataEncodesFlagsAndVint8Data) {
    LoopbackResponder server;
    const std::vector<std::uint8_t> body = {0xDE, 0xAD, 0xBE};
    const auto r = testabilityTcpSendData(loopbackConfig(server.port()), /*socket_id=*/0x0042,
                                          /*total_len=*/6, /*flags=*/0x00, body,
                                          /*timeout_ms=*/1000);
    EXPECT_TRUE(r.eok());

    // Request DAT: socketId(u16) + totalLen(u16) + flags(u8) + data vint8(n=3, DE AD BE).
    const auto dat = server.lastRequestDat();
    ASSERT_EQ(dat.size(), 2u + 2u + 1u + 2u + 3u);
    EXPECT_EQ(dat[0], 0x00u);  // socketId hi
    EXPECT_EQ(dat[1], 0x42u);  // socketId lo
    EXPECT_EQ(dat[2], 0x00u);  // totalLen hi
    EXPECT_EQ(dat[3], 0x06u);  // totalLen lo
    EXPECT_EQ(dat[4], 0x00u);  // flags (bit 7 reserved)
    EXPECT_EQ(dat[5], 0x00u);  // data vint8 n hi
    EXPECT_EQ(dat[6], 0x03u);  // data vint8 n lo = 3
    EXPECT_EQ(dat[7], 0xDEu);
    EXPECT_EQ(dat[8], 0xADu);
    EXPECT_EQ(dat[9], 0xBEu);
}

TEST(TestabilityClient, CloseSocketEncodesSocketIdInGivenGroup) {
    LoopbackResponder server;
    const auto r = testabilityCloseSocket(loopbackConfig(server.port()), tp::kGidTcp,
                                          /*socket_id=*/0x0042, /*timeout_ms=*/1000);
    EXPECT_TRUE(r.eok());
    const auto dat = server.lastRequestDat();
    ASSERT_EQ(dat.size(), 2u);
    EXPECT_EQ(dat[0], 0x00u);
    EXPECT_EQ(dat[1], 0x42u);
}

TEST(TestabilityClient, TcpListenEncodesRequestAndReturnsEOk) {
    LoopbackResponder server;
    // Listen-only: the synchronous E_OK is enough; the responder still emits an
    // accept Event afterwards, which this wrapper ignores (no persistent fd).
    const auto r = testabilityTcpListen(loopbackConfig(server.port()), /*listen_socket_id=*/0x0042,
                                        /*max_con=*/1, /*timeout_ms=*/1000);
    EXPECT_TRUE(r.eok());

    // Request DAT: listenSocketId(0x0042) + maxCon(0x0001) — same framing as
    // testabilityTcpListenAndAccept (shared SSOT in the .cpp).
    const auto dat = server.lastRequestDat();
    ASSERT_EQ(dat.size(), 4u);
    EXPECT_EQ(dat[0], 0x00u);
    EXPECT_EQ(dat[1], 0x42u);
    EXPECT_EQ(dat[2], 0x00u);
    EXPECT_EQ(dat[3], 0x01u);
}

TEST(TestabilityClient, ListenAndAcceptEncodesRequestAndParsesEvent) {
    LoopbackResponder server;
    bool triggered = false;
    const auto ev = testabilityTcpListenAndAccept(
        loopbackConfig(server.port()), /*listen_socket_id=*/0x0042, /*max_con=*/2,
        [&] { triggered = true; }, /*resp_timeout_ms=*/1000, /*event_timeout_ms=*/1000);

    // on_listening runs after the E_OK response and before the Event wait.
    EXPECT_TRUE(triggered);
    ASSERT_TRUE(ev.received);
    EXPECT_EQ(ev.listen_socket_id, 0x0042u);
    EXPECT_EQ(ev.new_socket_id, LoopbackResponder::kAcceptNewSocketId);
    EXPECT_EQ(ev.client_port, LoopbackResponder::kAcceptClientPort);
    EXPECT_EQ(ev.client_addr_be, ::htonl(INADDR_LOOPBACK));

    // Request DAT: listenSocketId(0x0042) + maxCon(0x0002).
    const auto dat = server.lastRequestDat();
    ASSERT_EQ(dat.size(), 4u);
    EXPECT_EQ(dat[0], 0x00u);
    EXPECT_EQ(dat[1], 0x42u);
    EXPECT_EQ(dat[2], 0x00u);
    EXPECT_EQ(dat[3], 0x02u);
}

}  // namespace
}  // namespace tc8::testability
