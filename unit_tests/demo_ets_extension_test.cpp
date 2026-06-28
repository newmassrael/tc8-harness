// Hermetic runtime proof of the IEtsExtension / IEtsEventSink seam: a fake sink
// records the facade calls so the demo extension can be driven WITHOUT a vsomeip
// application or a running DUT. This proves the seam CONTRACT end-to-end (an
// extension offers an event, registers a trigger method, and the trigger
// notifies — all through IEtsEventSink). The vsomeip-backed sink
// (makeEtsEventSink) and on-the-wire delivery are exercised separately by the
// tc8-dut build + the tester<->DUT topology run.

#include <cstdint>
#include <functional>
#include <map>
#include <vector>

#include <gtest/gtest.h>

#include "demo_ets_extension.h"
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
