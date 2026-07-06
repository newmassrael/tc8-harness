// Unit test of the warm-suspendInterface dispatcher (dut/dut_service/lifecycle_dispatcher.h).
// This is the drain->switch->hook marshalling that dut_main used to bury in untested
// anon-namespace glue; extracting it restores the "unit-test the fallible step" parity the
// retired ResumeEdge had. A RecordingExtension observes which hook fired and in what order;
// the four ETS facades are no-op stubs (the dispatcher forwards the context opaquely and the
// hooks under test ignore it). No vsomeip, no running DUT.

#include <cstdint>
#include <functional>
#include <memory>
#include <vector>

#include <gtest/gtest.h>

#include "ets_client_control.h"
#include "ets_control_channel.h"
#include "ets_event_sink.h"
#include "ets_io_host.h"
#include "fake_waker.h"
#include "lifecycle_dispatcher.h"

namespace {

using tc8::dut::EtsExtensionContext;
using tc8::dut::LifecycleDispatcher;
using tc8::dut::LifecycleEvent;
using tc8::dut::LifecycleSignal;
using tc8::dut::test::FakeWaker;

// Records the lifecycle hooks the dispatcher invokes, in order — so a transposed switch arm
// (Suspend -> onReactivate) or a lost/duplicated event is caught behaviorally.
class RecordingExtension : public tc8::dut::IEtsExtension {
public:
    void onSuspend(EtsExtensionContext&) override { calls.push_back(LifecycleEvent::Suspend); }
    void onReactivate(EtsExtensionContext&) override {
        calls.push_back(LifecycleEvent::Reactivate);
    }
    std::vector<LifecycleEvent> calls;
};

// No-op facades so an EtsExtensionContext can be constructed; the dispatcher forwards it and
// RecordingExtension ignores it.
struct StubSink : tc8::dut::IEtsEventSink {
    void offerEvent(std::uint16_t, const std::vector<std::uint16_t>&) override {}
    void notify(std::uint16_t, const std::vector<std::uint8_t>&) override {}
    void onMethod(std::uint16_t,
                  std::function<void(const std::vector<std::uint8_t>&)>) override {}
    void onRequestEx(
        std::uint16_t,
        std::function<tc8::dut::EtsReply(const std::vector<std::uint8_t>&)>) override {}
};
struct StubClient : tc8::dut::IEtsClientControl {
    void findService(std::uint16_t, std::uint16_t, std::uint8_t) override {}
    void subscribeEventgroup(std::uint16_t, std::uint16_t, std::uint16_t,
                             const std::vector<std::uint16_t>&, bool, std::uint8_t) override {}
    void stopSubscribeEventgroup(std::uint16_t, std::uint16_t, std::uint16_t) override {}
    void onSubscriptionStatus(std::uint16_t, std::uint16_t, std::uint16_t,
                              std::function<void(bool)>) override {}
    void callMethod(std::uint16_t, std::uint16_t, std::uint16_t,
                    const std::vector<std::uint8_t>&, bool, std::uint8_t) override {}
    void callMethodNoReturn(std::uint16_t, std::uint16_t, std::uint16_t,
                            const std::vector<std::uint8_t>&, bool, std::uint8_t) override {}
    void onResponse(
        std::uint16_t, std::uint16_t, std::uint16_t,
        std::function<void(std::uint8_t, const std::vector<std::uint8_t>&)>) override {}
};
struct StubControl : tc8::dut::IEtsControlChannel {
    void offerControlMethod(
        std::uint16_t, std::uint16_t, std::uint16_t, std::uint8_t,
        std::function<void(const std::vector<std::uint8_t>&)>) override {}
    void offerControlRequestEx(
        std::uint16_t, std::uint16_t, std::uint16_t, std::uint8_t,
        std::function<tc8::dut::EtsReply(const std::vector<std::uint8_t>&)>) override {}
};
struct StubIo : tc8::dut::IEtsIoHost {
    void adoptPollable(std::unique_ptr<tc8::IPollableService>) override {}
};

// Builds a dispatcher over a real LifecycleSignal (FakeWaker) + a RecordingExtension.
struct Fixture {
    StubSink sink;
    StubClient client;
    StubControl control;
    StubIo io;
    RecordingExtension ext;
    std::shared_ptr<LifecycleSignal> signal =
        std::make_shared<LifecycleSignal>(std::make_unique<FakeWaker>());
    LifecycleDispatcher dispatcher{signal, ext, EtsExtensionContext{sink, client, control, io}};
};

}  // namespace

TEST(LifecycleDispatcher, PollFdForwardsTheSignalsFd) {
    Fixture f;
    EXPECT_EQ(f.dispatcher.pollFd(), FakeWaker::kFd);
}

TEST(LifecycleDispatcher, NoPostedEventsDispatchesNothing) {
    Fixture f;
    f.dispatcher.onReadable();
    EXPECT_TRUE(f.ext.calls.empty());
}

TEST(LifecycleDispatcher, DispatchesEachEventToItsMatchingHookInOrder) {
    Fixture f;
    // A full suspend/re-offer cycle: onSuspend must fire before onReactivate, each mapped to
    // its own event — the enum->hook wiring that must not transpose.
    f.signal->post(LifecycleEvent::Suspend);
    f.signal->post(LifecycleEvent::Reactivate);
    f.dispatcher.onReadable();

    ASSERT_EQ(f.ext.calls.size(), 2u);
    EXPECT_EQ(f.ext.calls[0], LifecycleEvent::Suspend);
    EXPECT_EQ(f.ext.calls[1], LifecycleEvent::Reactivate);
}

TEST(LifecycleDispatcher, DispatchesAllEventsDrainedInOneWake) {
    Fixture f;
    // Two cycles coalesced into one drain still deliver all four hooks, in order.
    f.signal->post(LifecycleEvent::Suspend);
    f.signal->post(LifecycleEvent::Reactivate);
    f.signal->post(LifecycleEvent::Suspend);
    f.signal->post(LifecycleEvent::Reactivate);
    f.dispatcher.onReadable();

    const std::vector<LifecycleEvent> expected{
        LifecycleEvent::Suspend, LifecycleEvent::Reactivate, LifecycleEvent::Suspend,
        LifecycleEvent::Reactivate};
    EXPECT_EQ(f.ext.calls, expected);
}
