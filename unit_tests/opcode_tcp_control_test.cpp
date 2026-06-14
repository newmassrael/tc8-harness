#include <arpa/inet.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <unistd.h>

#include <atomic>
#include <cstdint>
#include <thread>
#include <vector>

#include <gtest/gtest.h>

#include "sce_integration/dut_control.h"
#include "tc8/upper_tester_protocol.h"

// OpcodeTcpControl drives the opcode UT over a synchronous SOCK_DGRAM round
// trip. The real opcode server (upper_tester_server) enumerates non-loopback
// interfaces and cannot run on plain loopback, so this exercises the adapter's
// request encoding + response parsing against a mock UT responder. The real
// server's socket behaviour is covered by the in-tree case suite.

namespace tc8 {
namespace {

// Minimal opcode UT responder on 127.0.0.1: echoes <opcode|0x80> <req_id>
// <status> <data> per the protocol, with a fabricated socket id for OpenTcp and
// an "established" boolean for QueryTcpEstablished.
class MockOpcodeResponder {
public:
    static constexpr std::uint8_t kSocketId = 0x07;

    MockOpcodeResponder() {
        fd_ = ::socket(AF_INET, SOCK_DGRAM, 0);
        sockaddr_in addr{};
        addr.sin_family = AF_INET;
        addr.sin_addr.s_addr = ::htonl(INADDR_LOOPBACK);
        addr.sin_port = 0;
        ::bind(fd_, reinterpret_cast<sockaddr *>(&addr), sizeof(addr));
        socklen_t len = sizeof(addr);
        ::getsockname(fd_, reinterpret_cast<sockaddr *>(&addr), &len);
        port_ = ntohs(addr.sin_port);
        thread_ = std::thread([this] { serve(); });
    }
    ~MockOpcodeResponder() {
        stop_ = true;
        ::shutdown(fd_, SHUT_RDWR);  // unblock the serve() recvfrom
        if (thread_.joinable()) {
            thread_.join();  // serve() has stopped touching fd_ before we close it
        }
        ::close(fd_);
    }
    std::uint16_t port() const { return port_; }
    // Opcode of the most recently served request — lets a test assert which UT
    // request a seam operation routed to (e.g. literal SEND vs pattern SEND).
    std::uint8_t lastOpcode() const { return last_opcode_.load(); }

private:
    void serve() {
        std::uint8_t buf[2048];
        while (!stop_) {
            sockaddr_in peer{};
            socklen_t plen = sizeof(peer);
            const ssize_t n = ::recvfrom(fd_, buf, sizeof(buf), 0,
                                         reinterpret_cast<sockaddr *>(&peer), &plen);
            if (n < 2) {
                if (stop_) break;
                continue;
            }
            const std::uint8_t opcode = buf[0];
            last_opcode_.store(opcode);
            std::vector<std::uint8_t> resp = {
                static_cast<std::uint8_t>(opcode | ut::kResponseBit), buf[1], ut::kStatusOk};
            if (opcode == ut::OpOpenTcpSocket) {
                resp.push_back(kSocketId);
            } else if (opcode == ut::OpQueryTcpEstablished) {
                resp.push_back(0x01);  // established
            }
            ::sendto(fd_, resp.data(), resp.size(), 0, reinterpret_cast<sockaddr *>(&peer),
                     plen);
        }
    }

    int fd_ = -1;
    std::uint16_t port_ = 0;
    std::thread thread_;
    std::atomic<bool> stop_{false};
    std::atomic<std::uint8_t> last_opcode_{0};
};

sce::OpcodeTcpControl makeControl(std::uint16_t port) {
    return sce::OpcodeTcpControl(::htonl(INADDR_LOOPBACK), port, /*src_ip_be=*/0,
                                 /*timeout_ms=*/1000);
}

TEST(OpcodeTcpControl, ConnectReturnsSocketId) {
    MockOpcodeResponder server;
    auto ctrl = makeControl(server.port());
    const auto conn = ctrl.connectTcp(sce::Endpoint{::htonl(0xAC100001), 8000}, sce::BindSpec{});
    ASSERT_TRUE(conn.has_value());
    EXPECT_EQ(conn->socket.id, MockOpcodeResponder::kSocketId);
    EXPECT_EQ(conn->peer.port, 8000u);
}

TEST(OpcodeTcpControl, AcceptPollsUntilEstablished) {
    MockOpcodeResponder server;
    auto ctrl = makeControl(server.port());
    bool triggered = false;
    const auto conn =
        ctrl.acceptTcp(sce::BindSpec{/*do_bind=*/true, 30750, 0}, [&] { triggered = true; });
    EXPECT_TRUE(triggered);
    ASSERT_TRUE(conn.has_value());
    EXPECT_EQ(conn->socket.id, MockOpcodeResponder::kSocketId);
    // The opcode model does not surface the client endpoint.
    EXPECT_EQ(conn->peer.addr_be, 0u);
}

TEST(OpcodeTcpControl, ListenReturnsSocketIdWithoutAccept) {
    MockOpcodeResponder server;
    auto ctrl = makeControl(server.port());
    // Listen-only: the passive OPEN returns the listener id immediately; unlike
    // acceptTcp there is no OpQueryTcpEstablished poll (the case drives its own
    // handshake-incomplete stimulus).
    const auto handle = ctrl.listenTcp(sce::BindSpec{/*do_bind=*/true, 30751, 0});
    ASSERT_TRUE(handle.has_value());
    EXPECT_EQ(handle->id, MockOpcodeResponder::kSocketId);
}

TEST(OpcodeTcpControl, SendAndCloseSucceed) {
    MockOpcodeResponder server;
    auto ctrl = makeControl(server.port());
    const std::vector<std::uint8_t> body = {'T', 'C', '8'};
    EXPECT_TRUE(ctrl.sendTcp(sce::DutSocket{MockOpcodeResponder::kSocketId}, body, 3));
    EXPECT_TRUE(ctrl.closeTcp(sce::DutSocket{MockOpcodeResponder::kSocketId}));
}

TEST(OpcodeTcpControl, SendLiteralUsesSendTcpDataOpcode) {
    // total_len == data.size(): the repeat is a no-op, so the literal
    // OpSendTcpData (0x06) request carries the bytes verbatim.
    MockOpcodeResponder server;
    auto ctrl = makeControl(server.port());
    const std::vector<std::uint8_t> body = {'T', 'C', '8'};
    EXPECT_TRUE(ctrl.sendTcp(sce::DutSocket{MockOpcodeResponder::kSocketId}, body,
                             static_cast<std::uint16_t>(body.size())));
    EXPECT_EQ(server.lastOpcode(), static_cast<std::uint8_t>(ut::OpSendTcpData));
}

TEST(OpcodeTcpControl, SendTotalLenRepeatRoutesToPatternOpcode) {
    // total_len > data.size() with a single-byte template: the bulk repeat
    // routes to OpSendTcpDataPattern (0x0A) so the DUT generates total_len
    // bytes past the literal OpSendTcpData kMaxPayload (256 B) cap, matching
    // the testability backend's one-byte template repeat.
    MockOpcodeResponder server;
    auto ctrl = makeControl(server.port());
    const std::vector<std::uint8_t> pattern = {0xC3U};
    EXPECT_TRUE(ctrl.sendTcp(sce::DutSocket{MockOpcodeResponder::kSocketId}, pattern,
                             /*total_len=*/4000U));
    EXPECT_EQ(server.lastOpcode(), static_cast<std::uint8_t>(ut::OpSendTcpDataPattern));
}

TEST(OpcodeTcpControl, NoServerFailsGracefully) {
    // Nothing listening on this loopback port — the round trip times out.
    auto ctrl = sce::OpcodeTcpControl(::htonl(INADDR_LOOPBACK), /*port=*/1, 0, /*timeout_ms=*/150);
    EXPECT_FALSE(
        ctrl.connectTcp(sce::Endpoint{::htonl(INADDR_LOOPBACK), 80}, sce::BindSpec{}).has_value());
    EXPECT_FALSE(ctrl.closeTcp(sce::DutSocket{1}));
}

}  // namespace
}  // namespace tc8
