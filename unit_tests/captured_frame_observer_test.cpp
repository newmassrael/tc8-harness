// Contract cover for the captured-frame observer seam
// (ICapturedFrameObserver / IFrameObservingService,
// src/sce_integration/captured_frame_observer.h): the type relationships and
// polymorphic dispatch a TestRunner relies on when it owns a frame-observing
// service via IBackgroundServiceOwner::adoptObservingService and fans every
// captured frame out to it after dispatch. The runner-side fan-out wiring itself
// is covered by compilation (the binary instantiates TestRunner<SM>) plus the
// tester<->DUT integration run, exactly as the adoptService ownership seam is
// (see arp_responder_test.cpp's PollableServiceSeam) — instantiating a TestRunner
// here would require a full generated SCXML state machine.

#include <memory>
#include <type_traits>
#include <variant>
#include <vector>

#include <gtest/gtest.h>

#include "sce_integration/captured_frame_observer.h"
#include "tc8/captured_event.h"
#include "tc8/pollable_service.h"

namespace {

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

}  // namespace
