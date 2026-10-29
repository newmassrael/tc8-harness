#include <array>
#include <cstdint>
#include <vector>

#include <gtest/gtest.h>

#include "sce_integration/udp_receive_answer.h"

// What a receive window's outcome becomes in the case's Captured context
// (udp_receive_answer.h). The verdict grades these fields, so the rule for when
// they count as an answer is the thing under test: a delivered probe and a PROVEN
// discard are answers; a silence, a refusal and a lost request are not.

namespace tc8::sce::udp {
namespace {

DutReceivedDatagram datagram(std::uint32_t src_ip, std::uint16_t src_port, std::uint16_t full_len,
                             std::vector<std::uint8_t> payload) {
    DutReceivedDatagram d;
    d.source = Endpoint{src_ip, src_port};
    d.full_len = full_len;
    d.payload = std::move(payload);
    return d;
}

TEST(UdpReceiveAnswer, ADeliveredProbeIsAnAnswerCarryingWhatTheDutSaw) {
    UdpCaptured c{};
    const auto out = DutUdpReceiveOutcome::observed(
        {datagram(0x0100A8C0U, 20001, 8, {0x10, 0x20, 0x30, 0x40, 0x50, 0x60, 0x70, 0x80})},
        /*path_proven=*/true);
    recordReceiveAnswer(c, out);
    EXPECT_TRUE(c.receive_answered);
    EXPECT_EQ(c.ut_received, 1U);
    EXPECT_EQ(c.ut_recv_src_ip, 0x0100A8C0U);
    EXPECT_EQ(c.ut_recv_src_port, 20001U);
    EXPECT_EQ(c.ut_recv_payload_len, 8U);
    EXPECT_EQ(c.ut_recv_payload_first16[0], 0x10U);
    EXPECT_EQ(c.ut_recv_payload_first16[7], 0x80U);
    EXPECT_EQ(c.ut_recv_payload_first16[8], 0U);
}

TEST(UdpReceiveAnswer, TheLengthIsTheDutsNotTheForwardedBytes) {
    // A testability arm forwards at most max_fwd bytes; the datagram's true length
    // still decides a length case, and the first16 cap holds.
    UdpCaptured c{};
    std::vector<std::uint8_t> forwarded(32);
    for (std::size_t i = 0; i < forwarded.size(); ++i) {
        forwarded[i] = static_cast<std::uint8_t>(0xA0 + i);
    }
    recordReceiveAnswer(c, DutUdpReceiveOutcome::observed(
                               {datagram(1, 2, 65507, forwarded)}, /*path_proven=*/true));
    EXPECT_EQ(c.ut_recv_payload_len, 65507U);
    for (std::size_t i = 0; i < 16; ++i) {
        EXPECT_EQ(c.ut_recv_payload_first16[i], static_cast<std::uint8_t>(0xA0 + i)) << i;
    }
}

TEST(UdpReceiveAnswer, AProvenDiscardIsAnAnswerThatNothingWasReceived) {
    UdpCaptured c{};
    recordReceiveAnswer(c, DutUdpReceiveOutcome::observed({}, /*path_proven=*/true));
    EXPECT_TRUE(c.receive_answered);
    EXPECT_EQ(c.ut_received, 0U);
}

TEST(UdpReceiveAnswer, ASilenceIsNotADiscard) {
    // Nothing delivered and no proof the path worked: the case must not read this
    // as the DUT discarding the probe.
    UdpCaptured c{};
    recordReceiveAnswer(c, DutUdpReceiveOutcome::observed({}, /*path_proven=*/false));
    EXPECT_FALSE(c.receive_answered);
}

TEST(UdpReceiveAnswer, ARefusalAndALostRequestAreNoAnswer) {
    UdpCaptured c{};
    recordReceiveAnswer(c, DutUdpReceiveOutcome::refused());
    EXPECT_FALSE(c.receive_answered);
    recordReceiveAnswer(c, DutUdpReceiveOutcome::noAnswer());
    EXPECT_FALSE(c.receive_answered);
}

TEST(UdpReceiveAnswer, ANewWindowReplacesTheLastOne) {
    UdpCaptured c{};
    recordReceiveAnswer(c, DutUdpReceiveOutcome::observed({datagram(7, 8, 4, {1, 2, 3, 4})}, true));
    recordReceiveAnswer(c, DutUdpReceiveOutcome::observed({}, true));
    EXPECT_TRUE(c.receive_answered);
    EXPECT_EQ(c.ut_received, 0U);
    EXPECT_EQ(c.ut_recv_src_ip, 0U);
    EXPECT_EQ(c.ut_recv_payload_len, 0U);
    EXPECT_EQ(c.ut_recv_payload_first16[0], 0U);
}

TEST(UdpReceiveAnswer, TheSecondWindowLandsInItsOwnFields) {
    UdpCaptured c{};
    recordReceiveAnswer(c, DutUdpReceiveOutcome::observed({datagram(0x0100A8C0U, 1, 1, {1})}, true));
    recordSecondReceiveAnswer(
        c, DutUdpReceiveOutcome::observed({datagram(0x030010ACU, 1, 1, {1})}, true));
    EXPECT_EQ(c.ut_recv_src_ip, 0x0100A8C0U);
    EXPECT_TRUE(c.receive2_answered);
    EXPECT_EQ(c.ut_received_p2, 1U);
    EXPECT_EQ(c.ut_recv_src_ip_p2, 0x030010ACU);
}

TEST(UdpReceiveAnswer, ThePortCountIsAnAnswerOnlyWhenTheDutGaveOne) {
    UdpCaptured c{};
    recordPortsAnswer(c, std::uint8_t{10});
    EXPECT_TRUE(c.receive_answered);
    EXPECT_EQ(c.ut_create_actual_count, 10U);
    UdpCaptured none{};
    recordPortsAnswer(none, std::nullopt);
    EXPECT_FALSE(none.receive_answered);
}

}  // namespace
}  // namespace tc8::sce::udp
