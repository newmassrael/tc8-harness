#pragma once

#include <memory>
#include <utility>

#include "tc8/pollable_service.h"

#include "ets_extension.h"     // IEtsExtension, EtsExtensionContext
#include "lifecycle_signal.h"  // LifecycleSignal, LifecycleEvent

namespace tc8::dut {

// Adapter that folds a LifecycleSignal's Waker fd into the DUT main loop's drainReady
// poll set (an IPollableService): on wake it drains the posted Suspend/Reactivate events
// and dispatches IEtsExtension::onSuspend / onReactivate on the main-loop thread, in FIFO
// order — the same threading contract as onRegister/onTick, never the detached suspend
// thread.
//
// Lifetime: holds a shared_ptr to the signal (the detached suspend thread posts to the same
// object) and BORROWS the extension (owned by dut_main, declared before the poll host that
// owns this dispatcher, so it outlives it). It holds the EtsExtensionContext BY VALUE — a
// copy of its four facade references — so it does NOT depend on the lifetime of dut_main's
// `ets_ctx` local (which, referencing the poll host, is necessarily destroyed before it).
// The copy's references target the same run-scoped facades, so the borrow is teardown-order-
// independent by construction, not by the "onReadable only runs inside the loop" convention.
//
// Extracted from dut_main so the drain->switch->hook marshalling (the fallible step) is
// unit-testable without a running DUT — see unit_tests/lifecycle_dispatcher_test.cpp. The
// no-default switch is `-Werror=switch`-gated in the tc8-dut build, so a new LifecycleEvent
// that is not dispatched fails the build.
class LifecycleDispatcher final : public tc8::IPollableService {
public:
    LifecycleDispatcher(std::shared_ptr<LifecycleSignal> signal, IEtsExtension& extension,
                        EtsExtensionContext ctx)
        : signal_(std::move(signal)), extension_(extension), ctx_(ctx) {}

    int pollFd() const override { return signal_->pollFd(); }

    void onReadable() override {
        for (const auto ev : signal_->drain()) {
            switch (ev) {
                case LifecycleEvent::Suspend:    extension_.onSuspend(ctx_);    break;
                case LifecycleEvent::Reactivate: extension_.onReactivate(ctx_); break;
            }
        }
    }

private:
    std::shared_ptr<LifecycleSignal> signal_;
    IEtsExtension& extension_;
    EtsExtensionContext ctx_;
};

}  // namespace tc8::dut
