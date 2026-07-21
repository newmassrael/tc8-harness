#pragma once

#include <memory>
#include <vector>

#include "tc8/captured_event.h"
#include "tc8/pollable_service.h"

#include "captured_frame_observer.h"

namespace tc8::sce {

// Run-scoped registry of the background services a case adopts onto the runner.
// Owns every adopted tc8::IPollableService (RAII-destroyed at teardown), keeps a
// non-owning observer view of the subset that ALSO observes captured frames, and
// fans every captured frame out to those observers. Factored out of the
// case-specific TestRunner<SM> template so the adopt + ownership + fan-out logic is
// a single source of truth and is directly unit-testable without instantiating a
// state machine. Single-threaded by contract: all calls run on the capture-loop
// thread (see ITestRunner), so it carries no locking.
class AdoptedServices {
public:
    // Own a pollable service for the whole run (no-op if null). Borrowed by the CLI
    // capture loop via pollable(); destroyed here at teardown.
    void adopt(std::unique_ptr<::tc8::IPollableService> service) {
        if (service) {
            services_.push_back(std::move(service));
        }
    }

    // Own a frame-observing service: record its observer role (a raw pointer that
    // stays valid because this object owns it for the run), then own it like any
    // pollable. static_cast (not dynamic_cast): the combined type statically IS-A
    // ICapturedFrameObserver, so the cross-base adjustment is a compile-time upcast
    // needing no RTTI. Delegates the ownership transfer to adopt() so it is
    // single-sourced.
    void adoptObserving(std::unique_ptr<IFrameObservingService> service) {
        if (service) {
            observers_.push_back(static_cast<ICapturedFrameObserver*>(service.get()));
            adopt(std::move(service));
        }
    }

    // Non-owning pointers to the owned services, for the CLI capture loop to poll.
    std::vector<::tc8::IPollableService*> pollable() const {
        std::vector<::tc8::IPollableService*> out;
        out.reserve(services_.size());
        for (const auto& s : services_) {
            out.push_back(s.get());
        }
        return out;
    }

    // Deliver `ev` to every frame-observing service. Called per CapturedEvent
    // sub-event AFTER the runner has dispatched it, on the single capture thread, so
    // observers must not block.
    void fanOutCapturedFrame(const ::tc8::CapturedEvent& ev) const {
        for (ICapturedFrameObserver* obs : observers_) {
            obs->onCapturedFrame(ev);
        }
    }

private:
    // Owners. Destroyed at teardown after the capture loop has returned; the
    // services hold no reference back into the runner, so order is not load-bearing.
    std::vector<std::unique_ptr<::tc8::IPollableService>> services_;
    // Non-owning view of the observing subset of `services_`; declared AFTER the
    // owners so it is destroyed first — its raw pointers never outlive the objects.
    std::vector<ICapturedFrameObserver*> observers_;
};

}  // namespace tc8::sce
