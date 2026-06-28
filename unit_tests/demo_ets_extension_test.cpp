// Unit test of the DEMO extension's use of the IEtsEventSink seam, against a
// FAKE sink that records the facade calls — no vsomeip application, no running
// DUT. SCOPE (honest): this verifies the demo extension drives the interface
// correctly (offers an event, registers a trigger method, the trigger notifies).
// It does NOT verify the production VsomeipEtsEventSink's vsomeip mapping
// (offer_event / create_payload / register_message_handler); that adapter is
// covered only by compilation (the tc8-dut build) plus the tester<->DUT topology
// run — EXCEPT its one fallible inbound-marshaling step, payloadBytes(), which is
// extracted and unit-tested directly below.

#include <cstddef>
#include <cstdint>
#include <functional>
#include <map>
#include <vector>

#include <gtest/gtest.h>

#include "demo_ets_extension.h"
#include "ets_event_sink.h"
#include "ets_extension.h"

namespace {

// Records every IEtsEventSink call so a test can assert what the extension did.
class FakeEtsEventSink : public tc8::dut::IEtsEventSink {
public:
    struct Offer {
        std::uint16_t event_id;
        std::vector<std::uint16_t> eventgroups;
    };
    struct Notification {
        std::uint16_t event_id;
        std::vector<std::uint8_t> payload;
    };

    void offerEvent(std::uint16_t event_id,
                    const std::vector<std::uint16_t>& eventgroups) override {
        offers.push_back({event_id, eventgroups});
    }
    void notify(std::uint16_t event_id,
                const std::vector<std::uint8_t>& payload) override {
        notifications.push_back({event_id, payload});
    }
    void onMethod(std::uint16_t method_id,
                  std::function<void(const std::vector<std::uint8_t>&)> handler) override {
        handlers[method_id] = std::move(handler);
    }

    std::vector<Offer> offers;
    std::vector<Notification> notifications;
    std::map<std::uint16_t, std::function<void(const std::vector<std::uint8_t>&)>> handlers;
};

}  // namespace

TEST(DemoEtsExtension, OnRegisterOffersEventAndArmsTrigger) {
    FakeEtsEventSink sink;
    tc8::dut::DemoEtsExtension ext;
    ext.onRegister(sink);

    // The demo event is offered on its two demo eventgroups, exactly once.
    ASSERT_EQ(sink.offers.size(), 1u);
    EXPECT_EQ(sink.offers[0].event_id, tc8::dut::kDemoEventId);
    EXPECT_EQ(sink.offers[0].eventgroups,
              (std::vector<std::uint16_t>{tc8::dut::kDemoEventgroupA,
                                          tc8::dut::kDemoEventgroupB}));

    // The trigger method is registered; nothing is notified until it fires.
    EXPECT_EQ(sink.handlers.count(tc8::dut::kDemoTriggerMethod), 1u);
    EXPECT_TRUE(sink.notifications.empty());
}

TEST(DemoEtsExtension, TriggerMethodNotifiesEventWithRequestPayload) {
    FakeEtsEventSink sink;
    tc8::dut::DemoEtsExtension ext;
    ext.onRegister(sink);

    // Firing the registered trigger notifies the demo event, echoing the
    // request payload — the core "method drives event" seam behavior.
    const std::vector<std::uint8_t> request{0x42, 0x43};
    sink.handlers[tc8::dut::kDemoTriggerMethod](request);

    ASSERT_EQ(sink.notifications.size(), 1u);
    EXPECT_EQ(sink.notifications[0].event_id, tc8::dut::kDemoEventId);
    EXPECT_EQ(sink.notifications[0].payload, request);
}

TEST(DemoEtsExtension, DefaultHooksAreNoOps) {
    // onTick / onStop carry no demo behavior; onTick must not emit on its own
    // (the demo event is trigger-driven, not cyclic).
    FakeEtsEventSink sink;
    tc8::dut::DemoEtsExtension ext;
    ext.onRegister(sink);
    sink.notifications.clear();

    ext.onTick(sink);
    ext.onStop();
    EXPECT_TRUE(sink.notifications.empty());

    // The demo opts 0x8001 cyclic-vs-triggered to the public default (cyclic).
    EXPECT_FALSE(ext.ets8001TriggerDriven());
}

// payloadBytes() — the extracted inbound-marshaling step from
// VsomeipEtsEventSink::onMethod (the production adapter's one fallible piece).
// Covers the null/zero guards and the byte copy without a live vsomeip message.
TEST(EtsEventSinkPayloadBytes, NullOrEmptyYieldsEmpty) {
    EXPECT_TRUE(tc8::dut::payloadBytes(nullptr, 0).empty());
    EXPECT_TRUE(tc8::dut::payloadBytes(nullptr, 4).empty());  // null data, nonzero len
    const std::uint8_t data[] = {0x01};
    EXPECT_TRUE(tc8::dut::payloadBytes(data, 0).empty());  // zero len, valid ptr
}

TEST(EtsEventSinkPayloadBytes, CopiesAllBytes) {
    const std::uint8_t data[] = {0xDE, 0xAD, 0xBE, 0xEF};
    EXPECT_EQ(tc8::dut::payloadBytes(data, sizeof(data)),
              (std::vector<std::uint8_t>{0xDE, 0xAD, 0xBE, 0xEF}));
}
