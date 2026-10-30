#include <optional>
#include <vector>

#include <gtest/gtest.h>

#include "demo_dut_extension.h"
#include "sce_integration/dut_call_intent.h"
#include "sce_integration/dut_control_extension.h"

// The demo DUT-control extension (examples/demo_dut_extension): the translation from a
// DUT's own primitive to the seam's vocabulary, and the negative control that a claim is
// read by its answer.

namespace tc8::sce::demo {
namespace {

// Stands in for the backend's service-primitive call: records what the extension sent and
// answers with a canned reply.
class CannedPrimitive final : public IServicePrimitiveControl {
public:
    DutPrimitiveReply reply;
    std::uint8_t gid = 0;
    std::uint8_t pid = 0;
    std::vector<std::uint8_t> sent;
    DutCallIntent intent_seen = DutCallIntent::kStimulus;

    DutPrimitiveReply call(std::uint8_t g, std::uint8_t p, const std::vector<std::uint8_t> &dat) override {
        gid = g;
        pid = p;
        sent = dat;
        intent_seen = DutCallIntentScope::current();
        return reply;
    }
};

DutPrimitiveReply answered(std::uint8_t state) {
    DutPrimitiveReply r;
    r.kind = DutCallOutcome::Kind::kDone;
    r.data = {state};
    return r;
}

TEST(DemoDutExtension, MapsEveryStateTheDutNames) {
    EXPECT_EQ(mapDemoState(kDemoStateEstablished), DutTcpState::kEstablished);
    EXPECT_EQ(mapDemoState(kDemoStateClosed), DutTcpState::kClosed);
    EXPECT_EQ(mapDemoState(kDemoStateTimeWait), DutTcpState::kTimeWait);
}

TEST(DemoDutExtension, AValueTheDutDoesNotDefineIsNotAnAnswer) {
    EXPECT_FALSE(mapDemoState(0x7F).has_value());
}

TEST(DemoDutExtension, AsksTheDutsPrimitiveForTheSocketAndReadsItsAnswer) {
    CannedPrimitive transport;
    transport.reply = answered(kDemoStateEstablished);
    auto ext = makeDemoDutExtension(transport);
    const auto state = ext->tcpStateQuery()->queryState(DutSocket{0x0102});
    EXPECT_EQ(transport.gid, kDemoGid);
    EXPECT_EQ(transport.pid, kDemoPidQueryState);
    EXPECT_EQ(transport.sent, (std::vector<std::uint8_t>{0x01, 0x02}));
    EXPECT_EQ(isEstablished(state), std::optional<bool>{true});
}

TEST(DemoDutExtension, TheQueryIsAGradedCall) {
    // A state read is an observation: a refusal is the DUT's answer, so the call must not be
    // recorded as a stimulus that did not take.
    CannedPrimitive transport;
    transport.reply = answered(kDemoStateEstablished);
    makeDemoDutExtension(transport)->tcpStateQuery()->queryState(DutSocket{1});
    EXPECT_EQ(transport.intent_seen, DutCallIntent::kGraded);
}

TEST(DemoDutExtension, ARefusalOrNoAnswerLeavesTheQueryFailed) {
    CannedPrimitive transport;
    auto ext = makeDemoDutExtension(transport);
    EXPECT_FALSE(ext->tcpStateQuery()->queryState(DutSocket{1}).has_value()) << "no answer";
    transport.reply.kind = DutCallOutcome::Kind::kRefused;
    EXPECT_FALSE(ext->tcpStateQuery()->queryState(DutSocket{1}).has_value()) << "refusal";
}

TEST(DemoDutExtension, ClaimsExactlyTheSeamItProvides) {
    CannedPrimitive transport;
    auto ext = makeDemoDutExtension(transport);
    EXPECT_EQ(ext->capabilities(), kCapTcpStateQuery);
    EXPECT_NE(ext->tcpStateQuery(), nullptr);
    EXPECT_EQ(ext->tcpInfoProbe(), nullptr);
    EXPECT_EQ(ext->arpControl(), nullptr);
}

// The negative control: an extension that claims the state query and misreports an
// ESTABLISHED socket. A case that declares kCapTcpStateQuery and asserts establishment
// reads the answer, not the claim, so it sees "not established" and its guard fails.
TEST(DemoDutExtension, AMislabellingExtensionIsReadByItsAnswerNotItsClaim) {
    CannedPrimitive transport;
    transport.reply = answered(kDemoStateEstablished);
    auto honest = makeDemoDutExtension(transport, /*mislabel_established=*/false);
    auto liar = makeDemoDutExtension(transport, /*mislabel_established=*/true);
    ASSERT_EQ(liar->capabilities(), honest->capabilities()) << "the claim is the same";
    EXPECT_EQ(isEstablished(honest->tcpStateQuery()->queryState(DutSocket{1})), std::optional<bool>{true});
    EXPECT_EQ(isEstablished(liar->tcpStateQuery()->queryState(DutSocket{1})), std::optional<bool>{false});
}

}  // namespace
}  // namespace tc8::sce::demo
