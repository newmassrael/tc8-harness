#include <optional>

#include <gtest/gtest.h>

#include "sce_integration/dut_control.h"
#include "sce_integration/dut_socket_control.h"

// The TCP state query answers an RFC 793 state and the cases that only need
// establishment derive it. A failed query stays a failed query, so a case keeps
// its third answer (neither established nor not) rather than reading it as "no".

namespace tc8::sce {
namespace {

TEST(DutTcpState, EstablishedIsEstablished) {
    EXPECT_EQ(isEstablished(DutTcpState::kEstablished), std::optional<bool>{true});
}

TEST(DutTcpState, EveryOtherNamedStateIsNotEstablished) {
    for (const auto s : {DutTcpState::kClosed, DutTcpState::kListen, DutTcpState::kSynSent,
                         DutTcpState::kSynReceived, DutTcpState::kFinWait1,
                         DutTcpState::kFinWait2, DutTcpState::kCloseWait, DutTcpState::kClosing,
                         DutTcpState::kLastAck, DutTcpState::kTimeWait,
                         DutTcpState::kOtherThanEstablished}) {
        EXPECT_EQ(isEstablished(s), std::optional<bool>{false}) << static_cast<int>(s);
    }
}

TEST(DutTcpState, AFailedQueryIsNotAnAnswer) {
    EXPECT_FALSE(isEstablished(std::nullopt).has_value());
}

// An unacknowledged send needs a raw transport: through the tester's kernel its ARP
// resolution would land in the very window the call exists to keep cold, so the
// opcode backend refuses instead of sending quietly.
TEST(DutUdpUnacknowledgedSend, OpcodeWithoutARawTransportRefuses) {
    OpcodeUdpControl udp(/*dut_ip_be=*/0, /*port=*/1, /*src_ip_be=*/0, /*timeout_ms=*/10);
    EXPECT_FALSE(udp.sendDatagramUnacknowledged(Endpoint{0, 1}, Endpoint{0, 2}, {1, 2, 3}));
}

// The testability socket id comes back in a response, so there is no sending
// without one.
TEST(DutUdpUnacknowledgedSend, TestabilityCannot) {
    TestabilityUdpControl udp(testability::TestabilityConfig{}, /*timeout_ms=*/10,
                              /*src_ip_be=*/0);
    EXPECT_FALSE(udp.sendDatagramUnacknowledged(Endpoint{0, 1}, Endpoint{0, 2}, {1, 2, 3}));
}

// The L2 send exists to keep the tester's kernel out of the window, so neither backend
// falls back to it without a wire, and a backend with no wire does not claim the bit.
TEST(DutUdpSendHeardAtL2, NoBackendSendsItWithoutAWire) {
    OpcodeUdpControl opcode(/*dut_ip_be=*/0, /*port=*/1, /*src_ip_be=*/0, /*timeout_ms=*/10);
    EXPECT_FALSE(opcode.sendDatagramHeardAtL2(Endpoint{0, 1}, Endpoint{0, 2}, {1, 2, 3}));

    TestabilityUdpControl testability_udp(testability::TestabilityConfig{}, /*timeout_ms=*/10,
                                          /*src_ip_be=*/0);
    EXPECT_FALSE(testability_udp.sendDatagramHeardAtL2(Endpoint{0, 1}, Endpoint{0, 2}, {1, 2, 3}));

    TestabilityControl no_wire(testability::TestabilityConfig{});
    EXPECT_EQ(no_wire.capabilities() & kCapUdpSendHeardAtL2, 0u);

    RawTransport wire;
    wire.iface = "unused-here";
    TestabilityControl with_wire(testability::TestabilityConfig{}, 10, 0, wire);
    EXPECT_NE(with_wire.capabilities() & kCapUdpSendHeardAtL2, 0u);
}

// With a wire, the three primitives go through the exchange in order and nothing else
// does: a kernel-routed step here would put the tester's ARP in the graded window.
TEST(DutUdpSendHeardAtL2, TestabilityCarriesItsThreePrimitivesOverTheExchange) {
    std::vector<std::uint8_t> pids;
    testability::TestabilityConfig wire_cfg;
    wire_cfg.exchange = [&pids](const std::vector<std::uint8_t> &req, int /*timeout_ms*/) {
        const auto h = testability::parseHeader(req.data(), req.size());
        pids.push_back(testability::pidOf(h->method_id));
        testability::Header resp = *h;
        resp.tid = testability::kTidResponse;
        resp.rid = testability::kRidEOk;
        const std::vector<std::uint8_t> socket_id{0x00, 0x07};
        return std::optional<std::vector<std::uint8_t>>(
            testability::buildMessage(resp, socket_id.data(), socket_id.size()));
    };
    TestabilityUdpControl udp(testability::TestabilityConfig{}, /*timeout_ms=*/10,
                              /*src_ip_be=*/0, wire_cfg);
    EXPECT_TRUE(udp.sendDatagramHeardAtL2(Endpoint{0, 1}, Endpoint{0, 2}, {1, 2, 3}));
    EXPECT_EQ(pids, (std::vector<std::uint8_t>{testability::kPidCreateAndBind,
                                               testability::kPidSendData,
                                               testability::kPidCloseSocket}));
}

}  // namespace
}  // namespace tc8::sce
