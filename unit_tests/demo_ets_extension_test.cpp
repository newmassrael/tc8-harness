// Unit test of the DEMO extension's use of the IEtsEventSink (server) and
// IEtsClientControl (client) seams, against FAKES that record the facade calls —
// no vsomeip application, no running DUT. SCOPE (honest): this verifies the demo
// extension drives the interfaces correctly — server: offers an event, registers
// a trigger method, the trigger notifies; client: subscribes/stops on a method,
// calls a remote method, captures the response, replies to a readback via onRequest,
// and rejects out-of-range input with an application Error via onRequestEx. It does
// NOT verify the production VsomeipEtsEventSink /
// VsomeipEtsClientControl vsomeip mapping (request_service / subscribe /
// create_request / create_response / register_message_handler); those adapters
// are covered only by compilation (the tc8-dut build), the boot-check's
// application-resolution assertion, and the tester<->DUT topology run — EXCEPT the
// one fallible inbound-marshaling step, payloadBytes(), which is extracted and
// unit-tested directly below.

#include <cstddef>
#include <cstdint>
#include <functional>
#include <map>
#include <memory>
#include <vector>

#include <gtest/gtest.h>

#include "demo_ets_extension.h"
#include "ets_client_control.h"
#include "ets_control_channel.h"
#include "ets_event_sink.h"
#include "ets_extension.h"
#include "ets_io_host.h"
#include "ets_payload.h"  // payloadBytes (vsomeip-free SSOT, exercised below)
#include "someip/protocol.h"  // someip::MessageType / ReturnCode (EtsReply fields)

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
    void onRequestEx(
        std::uint16_t method_id,
        std::function<tc8::dut::EtsReply(const std::vector<std::uint8_t>&)> handler)
        override {
        request_handlers[method_id] = std::move(handler);
    }

    std::vector<Offer> offers;
    std::vector<Notification> notifications;
    std::map<std::uint16_t, std::function<void(const std::vector<std::uint8_t>&)>> handlers;
    // Stores the reply-capable handlers from BOTH onRequestEx and the non-virtual
    // onRequest convenience (which forwards to onRequestEx), so a test can fire one
    // and inspect the chosen message type / Return Code / payload.
    std::map<std::uint16_t,
             std::function<tc8::dut::EtsReply(const std::vector<std::uint8_t>&)>>
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
    struct Find {
        std::uint16_t service;
        std::uint16_t instance;
        std::uint8_t major;
    };

    void findService(std::uint16_t service, std::uint16_t instance,
                     std::uint8_t major) override {
        finds.push_back({service, instance, major});
    }

    // noinline so GCC analyses this with the generic `const vector&` (unknown
    // size) instead of constant-propagating the size-1 events list inlined from
    // the demo lambda — that full-inlining is what trips a GCC 13
    // -Wstringop-overflow false positive on the vector-growth memmove (a known
    // IPA-CP artifact; a #pragma at the call site does NOT suppress mid-end
    // warnings). The code is correct; this just denies the optimizer the constant
    // that confuses it. Scoped to GCC only (Clang defines __GNUC__ but has no such
    // FP) and capped at GCC 13 so it self-retires when the toolchain advances.
#if defined(__GNUC__) && !defined(__clang__) && __GNUC__ <= 13
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
    void onSubscriptionStatus(std::uint16_t service, std::uint16_t instance,
                              std::uint16_t eventgroup,
                              std::function<void(bool)> handler) override {
        status_service = service;
        status_instance = instance;
        status_eventgroup = eventgroup;
        status_handler = std::move(handler);
    }
    void callMethod(std::uint16_t service, std::uint16_t instance, std::uint16_t method,
                    const std::vector<std::uint8_t>& payload, bool reliable,
                    std::uint8_t major) override {
        calls.push_back({service, instance, method, payload, reliable, major});
    }
    void callMethodNoReturn(std::uint16_t service, std::uint16_t instance,
                            std::uint16_t method, const std::vector<std::uint8_t>& payload,
                            bool reliable, std::uint8_t major) override {
        no_return_calls.push_back({service, instance, method, payload, reliable, major});
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

    std::vector<Find> finds;
    std::vector<Subscribe> subscribes;
    std::vector<Stop> stops;
    std::vector<Call> calls;
    std::vector<Call> no_return_calls;
    // The single onResponse registration the demo makes; a test fires it to
    // simulate the tester's Response arriving on a vsomeip thread.
    std::uint16_t response_service = 0;
    std::uint16_t response_instance = 0;
    std::uint16_t response_method = 0;
    std::function<void(std::uint8_t, const std::vector<std::uint8_t>&)> response_handler;
    // The single onSubscriptionStatus registration the demo makes; a test fires it
    // to simulate the tester's SubscribeEventgroupAck/Nack on a vsomeip thread.
    std::uint16_t status_service = 0;
    std::uint16_t status_instance = 0;
    std::uint16_t status_eventgroup = 0;
    std::function<void(bool)> status_handler;
};

// Records the IEtsControlChannel registration so a test can assert the inbound
// control service the extension offered and fire the trigger it bound.
class FakeEtsControlChannel : public tc8::dut::IEtsControlChannel {
public:
    void offerControlMethod(
        std::uint16_t service, std::uint16_t instance, std::uint16_t method,
        std::uint8_t major,
        std::function<void(const std::vector<std::uint8_t>&)> handler) override {
        control_service = service;
        control_instance = instance;
        control_method = method;
        control_major = major;
        control_handler = std::move(handler);
    }
    void offerControlRequestEx(
        std::uint16_t service, std::uint16_t instance, std::uint16_t method,
        std::uint8_t major,
        std::function<tc8::dut::EtsReply(const std::vector<std::uint8_t>&)> handler)
        override {
        request_control_service = service;
        request_control_instance = instance;
        request_control_major = major;
        // Stores the reply-capable handlers from BOTH offerControlRequestEx and the
        // non-virtual offerControlRequest convenience (which forwards here).
        control_request_handlers[method] = std::move(handler);
    }

    std::uint16_t control_service = 0;
    std::uint16_t control_instance = 0;
    std::uint16_t control_method = 0;
    std::uint8_t control_major = 0;
    std::function<void(const std::vector<std::uint8_t>&)> control_handler;
    std::uint16_t request_control_service = 0;
    std::uint16_t request_control_instance = 0;
    std::uint8_t request_control_major = 0;
    std::map<std::uint16_t,
             std::function<tc8::dut::EtsReply(const std::vector<std::uint8_t>&)>>
        control_request_handlers;
};

// Records the pollables an extension adopts through the I/O seam so a test can
// assert what it adopted (the demo adopts one — its DemoLoopbackReceiver).
class FakeEtsIoHost : public tc8::dut::IEtsIoHost {
public:
    void adoptPollable(std::unique_ptr<tc8::IPollableService> service) override {
        adopted.push_back(std::move(service));
    }
    std::vector<std::unique_ptr<tc8::IPollableService>> adopted;
};

}  // namespace

TEST(DemoEtsExtension, OnRegisterOffersEventAndArmsTrigger) {
    FakeEtsEventSink sink;
    FakeEtsClientControl client;
    FakeEtsControlChannel control;
    FakeEtsIoHost io;
    tc8::dut::EtsExtensionContext ctx{sink, client, control, io};
    tc8::dut::DemoEtsExtension ext;
    ext.onRegister(ctx);

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
    FakeEtsClientControl client;
    FakeEtsControlChannel control;
    FakeEtsIoHost io;
    tc8::dut::EtsExtensionContext ctx{sink, client, control, io};
    tc8::dut::DemoEtsExtension ext;
    ext.onRegister(ctx);

    // Firing the registered trigger notifies the demo event, echoing the
    // request payload — the core "method drives event" seam behavior.
    const std::vector<std::uint8_t> request{0x42, 0x43};
    sink.handlers[tc8::dut::kDemoTriggerMethod](request);

    ASSERT_EQ(sink.notifications.size(), 1u);
    EXPECT_EQ(sink.notifications[0].event_id, tc8::dut::kDemoEventId);
    EXPECT_EQ(sink.notifications[0].payload, request);
}

TEST(DemoEtsExtension, OnTickEmitsNothing) {
    // onTick emits no event on its own (the demo event is trigger-driven, not
    // cyclic). onStop's subscribe-stop is covered by OnStopStopsSubscription.
    FakeEtsEventSink sink;
    FakeEtsClientControl client;
    FakeEtsControlChannel control;
    FakeEtsIoHost io;
    tc8::dut::EtsExtensionContext ctx{sink, client, control, io};
    tc8::dut::DemoEtsExtension ext;
    ext.onRegister(ctx);
    sink.notifications.clear();

    ext.onTick(ctx);
    EXPECT_TRUE(sink.notifications.empty());

    // The demo opts 0x8001 cyclic-vs-triggered to the public default (cyclic).
    EXPECT_FALSE(ext.ets8001TriggerDriven());
}

TEST(DemoEtsExtension, OnReactivateReAnchorsActivationRelativeOffset) {
    FakeEtsEventSink sink;
    FakeEtsClientControl client;
    FakeEtsControlChannel control;
    FakeEtsIoHost io;
    tc8::dut::EtsExtensionContext ctx{sink, client, control, io};
    tc8::dut::DemoEtsExtension ext;
    ext.onRegister(ctx);

    ASSERT_EQ(sink.request_handlers.count(tc8::dut::kDemoActivationReadbackMethod), 1u);
    auto& offset = sink.request_handlers[tc8::dut::kDemoActivationReadbackMethod];

    // The periodic hook advances the re-activation-relative offset from zero.
    EXPECT_EQ(offset({}).payload, (std::vector<std::uint8_t>{0}));
    ext.onTick(ctx);
    ext.onTick(ctx);
    ext.onTick(ctx);
    EXPECT_EQ(offset({}).payload, (std::vector<std::uint8_t>{3}));

    // A warm suspendInterface re-offer re-anchors the offset to the re-activation
    // instant, so it re-applies from zero — the faithful shape an OEM uses to re-apply
    // a boot/re-activation-relative start offset after a warm re-offer (a deferred
    // state mutation the periodic hook reads, not a stateless event re-emit).
    ext.onReactivate(ctx);
    EXPECT_EQ(offset({}).payload, (std::vector<std::uint8_t>{0}));
    ext.onTick(ctx);
    ext.onTick(ctx);
    EXPECT_EQ(offset({}).payload, (std::vector<std::uint8_t>{2}));
}

TEST(DemoEtsExtension, OnSuspendFreezesActivationOffsetUntilReactivate) {
    FakeEtsEventSink sink;
    FakeEtsClientControl client;
    FakeEtsControlChannel control;
    FakeEtsIoHost io;
    tc8::dut::EtsExtensionContext ctx{sink, client, control, io};
    tc8::dut::DemoEtsExtension ext;
    ext.onRegister(ctx);

    auto& offset = sink.request_handlers[tc8::dut::kDemoActivationReadbackMethod];

    // Advance the offset, then suspend (a warm suspendInterface StopOffer): the offset
    // FREEZES across the de-offer window — onTick no longer advances it, the faithful
    // "activation-relative emission goes quiet on StopOffer" shape the symmetric onSuspend
    // hook enables (the cyclic stream stops on de-activation).
    ext.onTick(ctx);
    ext.onTick(ctx);
    EXPECT_EQ(offset({}).payload, (std::vector<std::uint8_t>{2}));
    ext.onSuspend(ctx);
    ext.onTick(ctx);
    ext.onTick(ctx);
    ext.onTick(ctx);
    EXPECT_EQ(offset({}).payload, (std::vector<std::uint8_t>{2}));  // frozen while suspended

    // The paired re-offer clears the freeze AND re-anchors to zero, so the offset restarts
    // from the re-activation instant (the first post-re-offer step is measured from the
    // start offset again). onSuspend fires before onReactivate in dut_main's loop.
    ext.onReactivate(ctx);
    EXPECT_EQ(offset({}).payload, (std::vector<std::uint8_t>{0}));
    ext.onTick(ctx);
    EXPECT_EQ(offset({}).payload, (std::vector<std::uint8_t>{1}));
}

TEST(DemoEtsExtension, SubscribeMethodDrivesClientControl) {
    FakeEtsEventSink sink;
    FakeEtsClientControl client;
    FakeEtsControlChannel control;
    FakeEtsIoHost io;
    tc8::dut::EtsExtensionContext ctx{sink, client, control, io};
    tc8::dut::DemoEtsExtension ext;
    ext.onRegister(ctx);

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
    FakeEtsControlChannel control;
    FakeEtsIoHost io;
    tc8::dut::EtsExtensionContext ctx{sink, client, control, io};
    tc8::dut::DemoEtsExtension ext;
    ext.onRegister(ctx);

    ext.onStop(ctx);
    ASSERT_EQ(client.stops.size(), 1u);
    EXPECT_EQ(client.stops[0].service, tc8::dut::kDemoTargetService);
    EXPECT_EQ(client.stops[0].instance, tc8::dut::kDemoTargetInstance);
    EXPECT_EQ(client.stops[0].eventgroup, tc8::dut::kDemoTargetEventgroup);
}

TEST(DemoEtsExtension, ControlMethodDeliversSubscribeInClientOnly) {
    FakeEtsEventSink sink;
    FakeEtsClientControl client;
    FakeEtsControlChannel control;
    FakeEtsIoHost io;
    tc8::dut::EtsExtensionContext ctx{sink, client, control, io};
    tc8::dut::DemoEtsExtension ext;
    ext.onRegister(ctx);

    // The demo offers a CONTROL service + method (on the inbound control channel)
    // that is distinct from the subscribe target (offering the target would
    // self-route the subscribe).
    EXPECT_EQ(control.control_service, tc8::dut::kDemoControlService);
    EXPECT_EQ(control.control_instance, tc8::dut::kDemoControlInstance);
    EXPECT_EQ(control.control_method, tc8::dut::kDemoControlSubscribeMethod);
    EXPECT_EQ(control.control_major, tc8::dut::kDemoTargetMajor);
    EXPECT_NE(control.control_service, tc8::dut::kDemoTargetService);
    ASSERT_TRUE(static_cast<bool>(control.control_handler));

    // Firing the control method drives the subscribe — the delivery path a
    // client-only DUT uses when its server-sink onMethod never fires.
    EXPECT_TRUE(client.subscribes.empty());
    control.control_handler({});
    ASSERT_EQ(client.subscribes.size(), 1u);
    EXPECT_EQ(client.subscribes[0].service, tc8::dut::kDemoTargetService);
    EXPECT_EQ(client.subscribes[0].eventgroup, tc8::dut::kDemoTargetEventgroup);
}

TEST(DemoEtsExtension, SubscriptionStatusBoundsLifetimeFromEstablishment) {
    FakeEtsEventSink sink;
    FakeEtsClientControl client;
    FakeEtsControlChannel control;
    FakeEtsIoHost io;
    tc8::dut::EtsExtensionContext ctx{sink, client, control, io};
    tc8::dut::DemoEtsExtension ext;
    ext.onRegister(ctx);

    // The demo observes its target eventgroup's subscription status.
    EXPECT_EQ(client.status_service, tc8::dut::kDemoTargetService);
    EXPECT_EQ(client.status_instance, tc8::dut::kDemoTargetInstance);
    EXPECT_EQ(client.status_eventgroup, tc8::dut::kDemoTargetEventgroup);
    ASSERT_TRUE(static_cast<bool>(client.status_handler));

    // Before establishment, ticks arm nothing — no stop is issued.
    for (int i = 0; i < tc8::dut::kDemoSubscriptionTicks + 1; ++i) ext.onTick(ctx);
    EXPECT_TRUE(client.stops.empty());

    // A Nack (established=false) must not arm the lifetime either.
    client.status_handler(false);
    for (int i = 0; i < tc8::dut::kDemoSubscriptionTicks + 1; ++i) ext.onTick(ctx);
    EXPECT_TRUE(client.stops.empty());

    // Establishment (Ack) arms the bounded lifetime: held for exactly
    // kDemoSubscriptionTicks ticks, then stopped once — the timer is anchored to
    // establishment, not to onRegister/startup.
    client.status_handler(true);
    for (int i = 0; i < tc8::dut::kDemoSubscriptionTicks - 1; ++i) {
        ext.onTick(ctx);
        EXPECT_TRUE(client.stops.empty());  // not yet expired
    }
    ext.onTick(ctx);  // the expiring tick
    ASSERT_EQ(client.stops.size(), 1u);
    EXPECT_EQ(client.stops[0].service, tc8::dut::kDemoTargetService);
    EXPECT_EQ(client.stops[0].instance, tc8::dut::kDemoTargetInstance);
    EXPECT_EQ(client.stops[0].eventgroup, tc8::dut::kDemoTargetEventgroup);

    // After expiry, further ticks do not re-stop (no spurious second StopSubscribe).
    ext.onTick(ctx);
    EXPECT_EQ(client.stops.size(), 1u);
}

TEST(DemoEtsExtension, CallMethodDrivesClientControl) {
    FakeEtsEventSink sink;
    FakeEtsClientControl client;
    FakeEtsControlChannel control;
    FakeEtsIoHost io;
    tc8::dut::EtsExtensionContext ctx{sink, client, control, io};
    tc8::dut::DemoEtsExtension ext;
    ext.onRegister(ctx);

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

TEST(DemoEtsExtension, FireForgetMethodDrivesClientControl) {
    FakeEtsEventSink sink;
    FakeEtsClientControl client;
    FakeEtsControlChannel control;
    FakeEtsIoHost io;
    tc8::dut::EtsExtensionContext ctx{sink, client, control, io};
    tc8::dut::DemoEtsExtension ext;
    ext.onRegister(ctx);

    ASSERT_EQ(sink.handlers.count(tc8::dut::kDemoFireForgetMethod), 1u);
    EXPECT_TRUE(client.no_return_calls.empty());

    const std::vector<std::uint8_t> request{0x33, 0x44};
    sink.handlers[tc8::dut::kDemoFireForgetMethod](request);

    // The Fire & Forget trigger drives callMethodNoReturn — recorded on the F&F
    // list, NOT the REQUEST list, so the two RPC kinds stay distinct.
    ASSERT_EQ(client.no_return_calls.size(), 1u);
    EXPECT_TRUE(client.calls.empty());
    const auto& c = client.no_return_calls[0];
    EXPECT_EQ(c.service, tc8::dut::kDemoTargetService);
    EXPECT_EQ(c.instance, tc8::dut::kDemoTargetInstance);
    EXPECT_EQ(c.method, tc8::dut::kDemoTargetMethod);
    EXPECT_EQ(c.payload, request);
    EXPECT_FALSE(c.reliable);
    EXPECT_EQ(c.major, tc8::dut::kDemoTargetMajor);
}

TEST(DemoEtsExtension, OnRegisterAdoptsAPollableReceiver) {
    FakeEtsEventSink sink;
    FakeEtsClientControl client;
    FakeEtsControlChannel control;
    FakeEtsIoHost io;
    tc8::dut::EtsExtensionContext ctx{sink, client, control, io};
    tc8::dut::DemoEtsExtension ext;
    ext.onRegister(ctx);

    // The demo adopts exactly one raw-receive pollable through the I/O seam — the
    // 4th seam, exercised in-tree like sink/client/control — with a valid fd.
    ASSERT_EQ(io.adopted.size(), 1u);
    EXPECT_GE(io.adopted[0]->pollFd(), 0);
}

TEST(DemoEtsExtension, ResponseIsCapturedAndReadbackReplies) {
    FakeEtsEventSink sink;
    FakeEtsClientControl client;
    FakeEtsControlChannel control;
    FakeEtsIoHost io;
    tc8::dut::EtsExtensionContext ctx{sink, client, control, io};
    tc8::dut::DemoEtsExtension ext;
    ext.onRegister(ctx);

    // The demo registered a response handler for the target method and a plain
    // readback method (onRequest convenience) that returns the captured payload.
    EXPECT_EQ(client.response_method, tc8::dut::kDemoTargetMethod);
    ASSERT_TRUE(static_cast<bool>(client.response_handler));
    ASSERT_EQ(sink.request_handlers.count(tc8::dut::kDemoReadbackMethod), 1u);

    // Before any response the readback replies an empty Response (E_OK).
    {
        const auto reply = sink.request_handlers[tc8::dut::kDemoReadbackMethod]({});
        EXPECT_EQ(reply.message_type, tc8::someip::MessageType::RESPONSE);
        EXPECT_EQ(reply.return_code, tc8::someip::ReturnCode::E_OK);
        EXPECT_TRUE(reply.payload.empty());
    }

    // A target Response: the readback replies a plain Response carrying it.
    const std::vector<std::uint8_t> response{0xAB, 0xCD};
    client.response_handler(0x00, response);
    {
        const auto reply = sink.request_handlers[tc8::dut::kDemoReadbackMethod]({});
        EXPECT_EQ(reply.message_type, tc8::someip::MessageType::RESPONSE);
        EXPECT_EQ(reply.return_code, tc8::someip::ReturnCode::E_OK);
        EXPECT_EQ(reply.payload, response);
    }
}

// The onRequestEx validating method inspects its OWN request: an out-of-range first
// byte is rejected with an application Error (ERROR / E_NOT_OK), an in-range one
// echoes back as a Response — the message-type + Return-Code choice onRequestEx adds
// over the Response-only onRequest, in its faithful motivating shape.
TEST(DemoEtsExtension, ValidatingMethodRejectsOutOfRangeInput) {
    FakeEtsEventSink sink;
    FakeEtsClientControl client;
    FakeEtsControlChannel control;
    FakeEtsIoHost io;
    tc8::dut::EtsExtensionContext ctx{sink, client, control, io};
    tc8::dut::DemoEtsExtension ext;
    ext.onRegister(ctx);

    ASSERT_EQ(sink.request_handlers.count(tc8::dut::kDemoValidatingMethod), 1u);
    auto& validate = sink.request_handlers[tc8::dut::kDemoValidatingMethod];

    // In range (< kDemoValidatingLimit): a Response echoing the request.
    {
        const std::vector<std::uint8_t> in{0x7F, 0x01};
        const auto reply = validate(in);
        EXPECT_EQ(reply.message_type, tc8::someip::MessageType::RESPONSE);
        EXPECT_EQ(reply.return_code, tc8::someip::ReturnCode::E_OK);
        EXPECT_EQ(reply.payload, in);
    }
    // Out of range (>= kDemoValidatingLimit): an Error message, no payload.
    {
        const auto reply = validate({tc8::dut::kDemoValidatingLimit});
        EXPECT_EQ(reply.message_type, tc8::someip::MessageType::ERROR);
        EXPECT_EQ(reply.return_code, tc8::someip::ReturnCode::E_NOT_OK);
        EXPECT_TRUE(reply.payload.empty());
    }
    // Empty request is rejected too (no first byte to validate).
    EXPECT_EQ(validate({}).message_type, tc8::someip::MessageType::ERROR);
}

// The non-virtual onRequest convenience forwards to onRequestEx as a plain
// Response (E_OK) carrying the handler's bytes — the common readback shape that
// keeps the simple API for OEM methods that never reply with an Error.
TEST(EtsEventSinkOnRequest, SugarRepliesResponseEOk) {
    FakeEtsEventSink sink;
    sink.onRequest(0x1234, [](const std::vector<std::uint8_t>& request) {
        return std::vector<std::uint8_t>(request.rbegin(), request.rend());
    });
    ASSERT_EQ(sink.request_handlers.count(0x1234), 1u);

    const auto reply = sink.request_handlers[0x1234]({0x01, 0x02});
    EXPECT_EQ(reply.message_type, tc8::someip::MessageType::RESPONSE);
    EXPECT_EQ(reply.return_code, tc8::someip::ReturnCode::E_OK);
    EXPECT_EQ(reply.payload, (std::vector<std::uint8_t>{0x02, 0x01}));
}

TEST(DemoEtsExtension, ControlReadbackRepliesPlainResponse) {
    FakeEtsEventSink sink;
    FakeEtsClientControl client;
    FakeEtsControlChannel control;
    FakeEtsIoHost io;
    tc8::dut::EtsExtensionContext ctx{sink, client, control, io};
    tc8::dut::DemoEtsExtension ext;
    ext.onRegister(ctx);

    // The demo offers a readback on the SAME control service as the F&F subscribe
    // trigger (offer-once, distinct method) — the client-only readback path.
    EXPECT_EQ(control.request_control_service, tc8::dut::kDemoControlService);
    EXPECT_EQ(control.request_control_service, control.control_service);
    ASSERT_EQ(control.control_request_handlers.count(tc8::dut::kDemoControlReadbackMethod), 1u);
    auto& readback = control.control_request_handlers[tc8::dut::kDemoControlReadbackMethod];

    // The control readback replies a plain Response carrying the captured payload.
    const std::vector<std::uint8_t> response{0xAB, 0xCD};
    client.response_handler(0x00, response);
    const auto reply = readback({});
    EXPECT_EQ(reply.message_type, tc8::someip::MessageType::RESPONSE);
    EXPECT_EQ(reply.return_code, tc8::someip::ReturnCode::E_OK);
    EXPECT_EQ(reply.payload, response);
}

// The non-virtual offerControlRequest convenience forwards to offerControlRequestEx
// as a plain Response (E_OK) carrying the handler's bytes — the common readback
// shape on the control channel, mirroring the event-sink onRequest sugar. Ids are
// arbitrary (not the demo's) — they are throwaway forwarding args.
TEST(EtsControlChannelOfferControlRequest, SugarRepliesResponseEOk) {
    FakeEtsControlChannel control;
    control.offerControlRequest(0x1111, 0x2222, 0x3333, 0x01,
                                [](const std::vector<std::uint8_t>& request) {
                                    return std::vector<std::uint8_t>(request.rbegin(),
                                                                     request.rend());
                                });
    ASSERT_EQ(control.control_request_handlers.count(0x3333), 1u);

    const auto reply = control.control_request_handlers[0x3333]({0x01, 0x02});
    EXPECT_EQ(reply.message_type, tc8::someip::MessageType::RESPONSE);
    EXPECT_EQ(reply.return_code, tc8::someip::ReturnCode::E_OK);
    EXPECT_EQ(reply.payload, (std::vector<std::uint8_t>{0x02, 0x01}));
}

// offerControlRequestEx (the reply-capable virtual itself) can answer with an Error
// message / non-E_OK Return Code — the control-channel counterpart of the sink's
// onRequestEx. Drives the Fake's Ex override directly with an Error-returning handler.
TEST(EtsControlChannelOfferControlRequest, ExCanReplyError) {
    FakeEtsControlChannel control;
    control.offerControlRequestEx(0x1111, 0x2222, 0x3333, 0x01,
                                  [](const std::vector<std::uint8_t>&) {
                                      return tc8::dut::EtsReply{
                                          tc8::someip::MessageType::ERROR,
                                          tc8::someip::ReturnCode::E_NOT_OK, {}};
                                  });
    ASSERT_EQ(control.control_request_handlers.count(0x3333), 1u);

    const auto reply = control.control_request_handlers[0x3333]({});
    EXPECT_EQ(reply.message_type, tc8::someip::MessageType::ERROR);
    EXPECT_EQ(reply.return_code, tc8::someip::ReturnCode::E_NOT_OK);
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
