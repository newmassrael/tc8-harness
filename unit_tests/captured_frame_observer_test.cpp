// Cover for the captured-frame observer seam and the registry that drives it:
//  - the seam types (ICapturedFrameObserver / IFrameObservingService,
//    src/sce_integration/captured_frame_observer.h) — the relationships and
//    polymorphic dispatch the runner relies on; and
//  - AdoptedServices (src/sce_integration/adopted_services.h), the run-scoped
//    registry TestRunner delegates to — the ACTUAL production adopt + ownership +
//    fan-out logic, tested directly (TestRunner<SM> only delegates to it, so this
//    exercises the real code without a generated SCXML state machine).

#include <memory>
#include <type_traits>
#include <variant>
#include <vector>

#include <gtest/gtest.h>

#include "sce_integration/adopted_services.h"
#include "sce_integration/captured_frame_observer.h"
#include "tc8/captured_event.h"
#include "tc8/pollable_service.h"

namespace {

using tc8::sce::AdoptedServices;
using tc8::sce::ICapturedFrameObserver;
using tc8::sce::IFrameObservingService;

// A frame-observing service IS-A pollable service AND a captured-frame observer, so
// the runner polls it and notifies it from one owned object with no run-time type
// query (adoptObservingService static_casts to the observer base).
static_assert(std::is_base_of_v<::tc8::IPollableService, IFrameObservingService>,
              "IFrameObservingService must model tc8::IPollableService");
static_assert(std::is_base_of_v<ICapturedFrameObserver, IFrameObservingService>,
              "IFrameObservingService must model ICapturedFrameObserver");

// Records onReadable() drains and the frames it was notified of, standing in for a
// reaction responder without a socket or a live capture loop.
class FakeFrameObservingService : public IFrameObservingService {
public:
    explicit FakeFrameObservingService(bool& destroyed_flag) : destroyed_(destroyed_flag) {}
    ~FakeFrameObservingService() override { destroyed_ = true; }
    int  pollFd() const override { return -1; }
    void onReadable() override { ++reads_; }
    void onCapturedFrame(const ::tc8::CapturedEvent& ev) override { observed_.push_back(ev); }

    int reads() const { return reads_; }
    const std::vector<::tc8::CapturedEvent>& observed() const { return observed_; }

private:
    int   reads_ = 0;
    std::vector<::tc8::CapturedEvent> observed_;
    bool& destroyed_;
};

// The runner owns adopted services as unique_ptr<IPollableService> and destroys
// them through that base pointer, while keeping a raw ICapturedFrameObserver* view
// — the exact derived->base ownership transfer adoptObservingService performs. The
// object must survive it and RAII-destroy through the pollable base.
TEST(CapturedFrameObserverSeam, OwnedThroughPollableBasePointerAndDestroyed) {
    bool destroyed = false;
    {
        std::vector<std::unique_ptr<::tc8::IPollableService>> owned;
        std::unique_ptr<IFrameObservingService> svc =
            std::make_unique<FakeFrameObservingService>(destroyed);
        ICapturedFrameObserver* observer = svc.get();  // the runner's non-owning view
        owned.push_back(std::move(svc));               // derived->base ownership transfer
        EXPECT_FALSE(destroyed);                       // owned while the window is open
        EXPECT_NE(observer, nullptr);
    }
    EXPECT_TRUE(destroyed);  // RAII through the IPollableService base pointer
}

// The runner notifies observers through the ICapturedFrameObserver base; verify the
// call dispatches to the concrete service with the frame it was handed, and that
// observing a frame is distinct from a socket drain.
TEST(CapturedFrameObserverSeam, OnCapturedFrameDispatchesPolymorphically) {
    bool destroyed = false;
    FakeFrameObservingService svc(destroyed);
    ICapturedFrameObserver& observer = svc;

    const ::tc8::CapturedEvent ev{::tc8::ArpFrame{}};
    observer.onCapturedFrame(ev);
    observer.onCapturedFrame(ev);

    ASSERT_EQ(svc.observed().size(), 2u);
    EXPECT_TRUE(std::holds_alternative<::tc8::ArpFrame>(svc.observed()[0]));
    EXPECT_EQ(svc.reads(), 0);  // observing a captured frame is not an onReadable drain
}

// A plain pollable service (no frame-observing role), to prove AdoptedServices owns
// and lists it but does NOT fan captured frames out to it.
class FakePollableService : public ::tc8::IPollableService {
public:
    explicit FakePollableService(bool& destroyed_flag) : destroyed_(destroyed_flag) {}
    ~FakePollableService() override { destroyed_ = true; }
    int  pollFd() const override { return -1; }
    void onReadable() override {}

private:
    bool& destroyed_;
};

// adoptObserving registers BOTH roles from one owned object: the service appears in
// the pollable() view AND receives fanned-out frames — the dual-registration the
// runner's adoptObservingService delegates here.
TEST(AdoptedServices, AdoptObservingPollsAndReceivesFrames) {
    bool destroyed = false;
    auto svc = std::make_unique<FakeFrameObservingService>(destroyed);
    FakeFrameObservingService* raw = svc.get();

    AdoptedServices adopted;
    adopted.adoptObserving(std::move(svc));

    ASSERT_EQ(adopted.pollable().size(), 1u);
    EXPECT_EQ(adopted.pollable()[0], raw);  // polled like any adopted service

    adopted.fanOutCapturedFrame(::tc8::CapturedEvent{::tc8::ArpFrame{}});
    ASSERT_EQ(raw->observed().size(), 1u);  // and notified of the frame
}

// A plain adopt()'d pollable is owned and polled but is NOT a frame observer, so
// fanOutCapturedFrame must skip it; an observing service adopted alongside still
// receives the frame.
TEST(AdoptedServices, FanOutReachesObserversOnlyNotPlainPollables) {
    bool pollable_destroyed = false;
    bool observer_destroyed = false;
    auto observer = std::make_unique<FakeFrameObservingService>(observer_destroyed);
    FakeFrameObservingService* observer_raw = observer.get();

    AdoptedServices adopted;
    adopted.adopt(std::make_unique<FakePollableService>(pollable_destroyed));
    adopted.adoptObserving(std::move(observer));

    EXPECT_EQ(adopted.pollable().size(), 2u);  // both owned + polled
    adopted.fanOutCapturedFrame(::tc8::CapturedEvent{::tc8::ArpFrame{}});
    EXPECT_EQ(observer_raw->observed().size(), 1u);  // only the observer is notified
}

// fanOut delivers each frame to EVERY registered observer; a null adopt is a no-op.
TEST(AdoptedServices, FanOutReachesAllObserversAndNullIsNoOp) {
    bool d1 = false, d2 = false;
    auto o1 = std::make_unique<FakeFrameObservingService>(d1);
    auto o2 = std::make_unique<FakeFrameObservingService>(d2);
    FakeFrameObservingService* r1 = o1.get();
    FakeFrameObservingService* r2 = o2.get();

    AdoptedServices adopted;
    adopted.adoptObserving(std::move(o1));
    adopted.adoptObserving(std::move(o2));
    adopted.adopt(nullptr);            // no-op
    adopted.adoptObserving(nullptr);   // no-op

    EXPECT_EQ(adopted.pollable().size(), 2u);
    adopted.fanOutCapturedFrame(::tc8::CapturedEvent{::tc8::ArpFrame{}});
    EXPECT_EQ(r1->observed().size(), 1u);
    EXPECT_EQ(r2->observed().size(), 1u);
}

// AdoptedServices owns its adopted services and RAII-destroys all of them at its own
// teardown — both plain and observing, through the IPollableService base pointer.
TEST(AdoptedServices, OwnsAndDestroysAdoptedServicesAtTeardown) {
    bool pollable_destroyed = false;
    bool observer_destroyed = false;
    {
        AdoptedServices adopted;
        adopted.adopt(std::make_unique<FakePollableService>(pollable_destroyed));
        adopted.adoptObserving(std::make_unique<FakeFrameObservingService>(observer_destroyed));
        EXPECT_FALSE(pollable_destroyed);
        EXPECT_FALSE(observer_destroyed);
    }
    EXPECT_TRUE(pollable_destroyed);
    EXPECT_TRUE(observer_destroyed);
}

}  // namespace
