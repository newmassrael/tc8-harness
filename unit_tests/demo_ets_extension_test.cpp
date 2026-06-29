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
#include "ets_client_control.h"
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
    void onRequest(
        std::uint16_t method_id,
        std::function<std::vector<std::uint8_t>(const std::vector<std::uint8_t>&)> handler)
        override {
        request_handlers[method_id] = std::move(handler);
    }

    std::vector<Offer> offers;
    std::vector<Notification> notifications;
    std::map<std::uint16_t, std::function<void(const std::vector<std::uint8_t>&)>> handlers;
    std::map<std::uint16_t,
             std::function<std::vector<std::uint8_t>(const std::vector<std::uint8_t>&)>>
        request_handlers;
};

// Records every IEtsClientControl call so a test can assert what the extension
// drove on the client surface (vsomeip-free, no running DUT).
class FakeEtsClientControl : public tc8::dut::IEtsClientControl {
public:
    struct Subscribe {
        std::uint16_t service;
        std::uint16_t instance;
        std::uint16_t eventgroup;
        std::vector<std::uint16_t> events;
        bool reliable;
        std::uint8_t major;
    };
    struct Stop {
        std::uint16_t service;
        std::uint16_t instance;
        std::uint16_t eventgroup;
    };

    // noinline so GCC analyses this with the generic `const vector&` (unknown
    // size) instead of constant-propagating the size-1 events list inlined from
    // the demo lambda — that full-inlining is what trips a GCC 13
    // -Wstringop-overflow false positive on the vector-growth memmove. The code
    // is correct; this just denies the optimizer the constant that confuses it.
#if defined(__GNUC__)
    [[gnu::noinline]]
#endif
    void subscribeEventgroup(std::uint16_t service, std::uint16_t instance,
                             std::uint16_t eventgroup,
                             const std::vector<std::uint16_t>& events, bool reliable,
                             std::uint8_t major) override {
        subscribes.push_back({service, instance, eventgroup, events, reliable, major});
    }
    void stopSubscribeEventgroup(std::uint16_t service, std::uint16_t instance,
                                 std::uint16_t eventgroup) override {
        stops.push_back({service, instance, eventgroup});
    }
    void callMethod(std::uint16_t service, std::uint16_t instance, std::uint16_t method,
                    const std::vector<std::uint8_t>& payload, bool reliable,
                    std::uint8_t major) override {
        calls.push_back({service, instance, method, payload, reliable, major});
    }
    void onResponse(std::uint16_t service, std::uint16_t instance, std::uint16_t method,
                    std::function<void(std::uint8_t, const std::vector<std::uint8_t>&)>
                        handler) override {
        response_service = service;
        response_instance = instance;
        response_method = method;
        response_handler = std::move(handler);
    }

    struct Call {
        std::uint16_t service;
        std::uint16_t instance;
        std::uint16_t method;
        std::vector<std::uint8_t> payload;
        bool reliable;
        std::uint8_t major;
    };

    std::vector<Subscribe> subscribes;
    std::vector<Stop> stops;
    std::vector<Call> calls;
    // The single onResponse registration the demo makes; a test fires it to
    // simulate the tester's Response arriving on a vsomeip thread.
    std::uint16_t response_service = 0;
    std::uint16_t response_instance = 0;
    std::uint16_t response_method = 0;
    std::function<void(std::uint8_t, const std::vector<std::uint8_t>&)> response_handler;
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
    // onTick emits nothing on its own (the demo event is trigger-driven, not
    // cyclic); onStop emits no event. With no client control handed here, onStop
    // also drives no subscribe-stop (that path is covered above).
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

TEST(DemoEtsExtension, SubscribeMethodDrivesClientControl) {
    FakeEtsEventSink sink;
    FakeEtsClientControl client;
    tc8::dut::DemoEtsExtension ext;
    // Mirror dut_main's order: client control handed before onRegister.
    ext.onRegisterClientControl(client);
    ext.onRegister(sink);

    // The subscribe method is registered and nothing is subscribed until it fires.
    ASSERT_EQ(sink.handlers.count(tc8::dut::kDemoSubscribeMethod), 1u);
    EXPECT_TRUE(client.subscribes.empty());

    // Firing it drives one subscribe to the synthetic target eventgroup (UDP).
    sink.handlers[tc8::dut::kDemoSubscribeMethod]({});
    ASSERT_EQ(client.subscribes.size(), 1u);
    const auto& s = client.subscribes[0];
    EXPECT_EQ(s.service, tc8::dut::kDemoTargetService);
    EXPECT_EQ(s.instance, tc8::dut::kDemoTargetInstance);
    EXPECT_EQ(s.eventgroup, tc8::dut::kDemoTargetEventgroup);
    EXPECT_EQ(s.events, (std::vector<std::uint16_t>{tc8::dut::kDemoTargetEvent}));
    EXPECT_FALSE(s.reliable);
    EXPECT_EQ(s.major, tc8::dut::kDemoTargetMajor);
}

TEST(DemoEtsExtension, OnStopStopsSubscription) {
    FakeEtsEventSink sink;
    FakeEtsClientControl client;
    tc8::dut::DemoEtsExtension ext;
    ext.onRegisterClientControl(client);
    ext.onRegister(sink);

    ext.onStop();
    ASSERT_EQ(client.stops.size(), 1u);
    EXPECT_EQ(client.stops[0].service, tc8::dut::kDemoTargetService);
    EXPECT_EQ(client.stops[0].instance, tc8::dut::kDemoTargetInstance);
    EXPECT_EQ(client.stops[0].eventgroup, tc8::dut::kDemoTargetEventgroup);
}

TEST(DemoEtsExtension, SubscribeMethodIsNoOpWithoutClientControl) {
    // Without onRegisterClientControl the handler captured a null facade — firing
    // it must not crash and drives nothing. onStop is likewise a no-op.
    FakeEtsEventSink sink;
    tc8::dut::DemoEtsExtension ext;
    ext.onRegister(sink);
    ASSERT_EQ(sink.handlers.count(tc8::dut::kDemoSubscribeMethod), 1u);
    sink.handlers[tc8::dut::kDemoSubscribeMethod]({});  // no client → no-op, no crash
    ext.onStop();
    SUCCEED();
}

TEST(DemoEtsExtension, CallMethodDrivesClientControl) {
    FakeEtsEventSink sink;
    FakeEtsClientControl client;
    tc8::dut::DemoEtsExtension ext;
    ext.onRegisterClientControl(client);
    ext.onRegister(sink);

    ASSERT_EQ(sink.handlers.count(tc8::dut::kDemoCallMethod), 1u);
    EXPECT_TRUE(client.calls.empty());

    const std::vector<std::uint8_t> request{0x11, 0x22};
    sink.handlers[tc8::dut::kDemoCallMethod](request);

    ASSERT_EQ(client.calls.size(), 1u);
    const auto& c = client.calls[0];
    EXPECT_EQ(c.service, tc8::dut::kDemoTargetService);
    EXPECT_EQ(c.instance, tc8::dut::kDemoTargetInstance);
    EXPECT_EQ(c.method, tc8::dut::kDemoTargetMethod);
    EXPECT_EQ(c.payload, request);
    EXPECT_FALSE(c.reliable);
    EXPECT_EQ(c.major, tc8::dut::kDemoTargetMajor);
}

TEST(DemoEtsExtension, ResponseIsCapturedAndReadbackReplies) {
    FakeEtsEventSink sink;
    FakeEtsClientControl client;
    tc8::dut::DemoEtsExtension ext;
    ext.onRegisterClientControl(client);
    ext.onRegister(sink);

    // The demo registered a response handler for the target method and a
    // reply-capable readback method.
    EXPECT_EQ(client.response_method, tc8::dut::kDemoTargetMethod);
    ASSERT_TRUE(static_cast<bool>(client.response_handler));
    ASSERT_EQ(sink.request_handlers.count(tc8::dut::kDemoReadbackMethod), 1u);

    // Before any response the readback replies empty.
    EXPECT_TRUE(sink.request_handlers[tc8::dut::kDemoReadbackMethod]({}).empty());

    // Simulate the tester's Response arriving; the readback then replies with it.
    const std::vector<std::uint8_t> response{0xAB, 0xCD};
    client.response_handler(0x00, response);
    EXPECT_EQ(sink.request_handlers[tc8::dut::kDemoReadbackMethod]({}), response);
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
