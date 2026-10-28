// SOMEIP_ETS_097: is the DUT's reconnect an answer to the second Offer?
//
// The reference DUT retries a refused connect every 100 ms without limit, so on the
// wire it only ever reaches the "may be its own retry" outcome. The other outcomes
// are the ones a conformant DUT of another design reaches, and nothing on the wire
// here would ever exercise them. So the decision is pinned in its two halves: the
// pure attribution of the retries the stimulus observed, and the case's own machine
// and dispatch driven with synthetic frames through each arm.

#include <gtest/gtest.h>

#include <cstdint>
#include <vector>

#include "sce_integration/cases/someip_ets_097.h"
#include "stimulus/someip_sd_builder.h"
#include "tc8/captured_event.h"
#include "tc8/protocol_frames/someip_frame.h"
#include "tc8/protocol_frames/tcp_frame.h"

namespace {

using Traits = ::tc8::sce::TestCaseTraits<::tc8::sce::cases::SomeipEts097SM>;
using SM = ::tc8::sce::cases::SomeipEts097SM;
using State = Traits::State;

// --- The attribution of the DUT's unprompted retries -----------------------------

TEST(SomeipEts097Attribution, FewerRetriesThanSampledIsQuietAndNoOwnRetryIsDue) {
    // The last wait saw a whole quiet window, after zero, one or two retries.
    const std::int64_t r[3] = {100'000, 200'000, 0};
    for (int count = 0; count < Traits::kRetriesSampled; ++count) {
        const auto a = Traits::attributeRetries(r, count);
        EXPECT_EQ(a.offer_at_us, 0) << count;
        EXPECT_EQ(a.retry_earliest_us, 0) << count;
        EXPECT_FALSE(a.unsteady) << count;
    }
}

TEST(SomeipEts097Attribution, SteadyRetriesPutTheOfferMidPeriodWithAQuarterMargin) {
    const std::int64_t r[3] = {1'000'000, 1'100'000, 1'200'000};
    const auto a = Traits::attributeRetries(r, 3);
    EXPECT_EQ(a.offer_at_us, 1'250'000);
    EXPECT_EQ(a.retry_earliest_us, 1'275'000);
    EXPECT_FALSE(a.unsteady);
}

TEST(SomeipEts097Attribution, AnUnsteadyPeriodLeavesNoInstantFreeOfAnOwnRetry) {
    // A doubling back-off: the next retry cannot be placed from two periods.
    const std::int64_t r[3] = {1'000'000, 1'100'000, 1'300'000};
    const auto a = Traits::attributeRetries(r, 3);
    EXPECT_TRUE(a.unsteady);
    EXPECT_EQ(a.offer_at_us, 0);
}

// --- The machine's arms ---------------------------------------------------------

constexpr std::uint16_t kServiceId = 0xF4E7;  // the DUT's own service (phase 1)
constexpr std::int64_t kOfferUs = 5'000'000;  // when the second Offer went out

class SomeipEts097Machine : public ::testing::Test {
protected:
    void SetUp() override {
        expected.service_id = kServiceId;
        sm.initialize();
        feedSd(sdPayloadOf(offerFromDut()));
        ASSERT_EQ(sm.getCurrentState(), State::Awaiting_subscribe_and_reconnect);
        captured.reconnect_offer_ts_us = kOfferUs;
    }

    static std::vector<std::uint8_t> offerFromDut() {
        ::tc8::stimulus::OfferServiceTarget t{};
        t.service_id = kServiceId;
        return ::tc8::stimulus::buildOfferService(t);
    }

    static std::vector<std::uint8_t> subscribeWithTcpOption() {
        ::tc8::stimulus::SubscribeEventgroupParams p{};
        p.target.service_id = 0xF4E9;
        p.tester_endpoint.ipv4_be = 0x0200A8C0U;
        p.tester_endpoint.port = 40000;
        p.tester_endpoint.l4proto = 0x06;
        return ::tc8::stimulus::buildSubscribeEventgroup(p);
    }

    // The SD payload: what follows the 16-byte SOME/IP header.
    static std::vector<std::uint8_t> sdPayloadOf(const std::vector<std::uint8_t> &message) {
        return std::vector<std::uint8_t>(message.begin() + 16, message.end());
    }

    void feedSd(const std::vector<std::uint8_t> &payload) {
        ::tc8::SomeIpFrame f{};
        f.service_id = 0xFFFF;
        f.method_id = 0x8100;
        f.message_type = 0x02;
        f.payload_data = payload.data();
        f.payload_len = static_cast<std::uint32_t>(payload.size());
        Traits::dispatch(captured, sm, ::tc8::CapturedEvent{f});
    }

    void feedSubscribe() { feedSd(sdPayloadOf(subscribeWithTcpOption())); }

    void feedSyn(std::int64_t at_us) {
        ::tc8::TcpFrame seg{};
        seg.src_port = 42000;
        seg.dst_port = Traits::kTesterReliablePort;
        seg.flags = Traits::kTcpFlagSyn;
        seg.observed_ts_us = at_us;
        Traits::dispatch(captured, sm, ::tc8::CapturedEvent{seg});
    }

    ::tc8::SomeIpCaptured captured{};
    ::tc8::SomeIpExpected expected{};
    SM sm{captured, expected};
};

TEST_F(SomeipEts097Machine, ARetryRefusedBeforeTheOfferIsNotTheAnswer) {
    feedSyn(kOfferUs - 1);
    EXPECT_EQ(sm.getCurrentState(), State::Awaiting_subscribe_and_reconnect);
}

TEST_F(SomeipEts097Machine, AfterAQuietWindowASynAfterTheOfferIsTheAnswer) {
    captured.spontaneous_retry_earliest_ts_us = 0;
    feedSyn(kOfferUs + 30'000'000);  // any delay within the window: no own retry is due
    EXPECT_EQ(sm.getCurrentState(), State::Awaiting_subscribe);
    feedSubscribe();
    EXPECT_EQ(sm.getCurrentState(), State::Pass);
}

TEST_F(SomeipEts097Machine, ASynBeforeTheOwnRetryIsDueIsTheAnswer) {
    captured.spontaneous_retry_earliest_ts_us = kOfferUs + 25'000;
    feedSyn(kOfferUs + 24'999);
    EXPECT_EQ(sm.getCurrentState(), State::Awaiting_subscribe);
}

TEST_F(SomeipEts097Machine, ASynOnceTheOwnRetryIsDueCannotBeAttributed) {
    captured.spontaneous_retry_earliest_ts_us = kOfferUs + 25'000;
    feedSyn(kOfferUs + 25'000);
    EXPECT_EQ(sm.getCurrentState(), State::Inconclusive_reconnect_not_attributable_to_offer);
}

TEST_F(SomeipEts097Machine, TheSubscribeMayComeBeforeTheReconnect) {
    feedSubscribe();
    EXPECT_EQ(sm.getCurrentState(), State::Awaiting_reconnect);
    feedSyn(kOfferUs + 1);
    EXPECT_EQ(sm.getCurrentState(), State::Pass);
}

TEST_F(SomeipEts097Machine, AnAckedSegmentToThePortIsNoReconnect) {
    ::tc8::TcpFrame seg{};
    seg.dst_port = Traits::kTesterReliablePort;
    seg.flags = Traits::kTcpFlagAck;
    seg.observed_ts_us = kOfferUs + 1;
    Traits::dispatch(captured, sm, ::tc8::CapturedEvent{seg});
    EXPECT_EQ(sm.getCurrentState(), State::Awaiting_subscribe_and_reconnect);
}

}  // namespace
