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

}  // namespace
}  // namespace tc8::sce
