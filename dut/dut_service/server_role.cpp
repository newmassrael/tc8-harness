#include "server_role.h"

#include <chrono>
#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <memory>
#include <optional>
#include <string>
#include <thread>
#include <utility>
#include <vector>

#include <CommonAPI/CommonAPI.hpp>

#include "env_flag.h"
#include "ets2_impl.h"
#include "ets_extension.h"
#include "ets_factory.h"
#include "ets_field_access.h"
#include "ets_impl.h"
#include "lifecycle_signal.h"

namespace tc8::dut {

namespace {

// IEtsFieldAccess over the primary registered stub. The stub outlives every
// re-register (suspendInterface re-offers the same object), so the value an
// extension sets is the one a re-offer publishes.
class StubFieldAccess final : public IEtsFieldAccess {
public:
    explicit StubFieldAccess(std::shared_ptr<EtsImpl> impl) : impl_(std::move(impl)) {}

    std::optional<std::vector<std::uint8_t>> testFieldUint8Array() const override {
        return impl_->testFieldUint8ArrayValue();
    }
    bool setTestFieldUint8Array(std::vector<std::uint8_t> value) override {
        impl_->setTestFieldUint8ArrayValue(std::move(value));
        return true;
    }

private:
    std::shared_ptr<EtsImpl> impl_;
};

}  // namespace

ServerRole::ServerRole(std::shared_ptr<CommonAPI::Runtime> runtime,
                       const IEtsExtension& extension,
                       std::shared_ptr<LifecycleSignal> lifecycle)
    : runtime_(std::move(runtime)) {
    namespace ed = ets_deploy;

    impl_ = createEtsStub();
    if (!runtime_->registerService(ed::kDomain, ed::kInstance, impl_)) {
        std::fprintf(stderr, "tc8-dut: registerService failed\n");
        // Hard-exit — avoid static destructors running vsomeip shutdown against a
        // half-initialised routing manager, which hangs the process.
        std::_Exit(1);
    }
    std::printf("tc8-dut: %s registered (domain=%s instance=%s)\n", ed::kInterface,
                ed::kDomain, ed::kInstance);

    // §5.1.6 SOMEIP_ETS_086/087/093/121 — seed the four Table 2 fields (notifiers
    // 0x8005..0x8008) so CommonAPI has a payload to send as each field's initial
    // Notification on every SubscribeEventgroupAck. Without one vsomeip logs "Event
    // payload not (yet) set" and skips the initial event, so the Explicit Initial
    // Data Control path stays unobservable. TestFieldUINT8 takes the extension's
    // value (0x42 by default); seedFields publishes every value, 0 included.
    impl_->seedFields(extension.testFieldUint8InitialValue());
    fields_ = std::make_unique<StubFieldAccess>(impl_);

    // Single emission engine (one producer per event). 0x8001/TestEventUINT8 is
    // CYCLIC by default — the DUT's pre-existing unconditional 250 ms cadence the
    // §5.1.5 suite relies on — unless the OEM extension opts it into a TRIGGERED
    // source (armed by triggerEventUINT8), letting its must-NOT-send-0x8001 cases
    // hold. The four new events are always TRIGGERED — they fire only after their
    // triggerEventX Method, so must-NOT-send cases hold. Sources are wired here;
    // start() is deferred to startEmission() (after the optional SI2 source is
    // added) and stop() to stopEmission(). The per-source payload counter is owned
    // by the controller and passed into each closure (no hidden statics). Firing
    // routes through the (registered) stub, so this is valid only in the server
    // role — which is exactly when a ServerRole exists.
    impl_->setEmissionController(&emission_);
    auto fireBasic = [impl = impl_](uint8_t v) { impl->fireTestEventUINT8Event(v); };
    if (extension.ets8001TriggerDriven()) {
        emission_.addTriggeredSource(std::string(ets_event::kBasic), fireBasic);
    } else {
        emission_.addCyclicSource(std::string(ets_event::kBasic), fireBasic,
                                  std::chrono::milliseconds(250));
    }
    emission_.addTriggeredSource(std::string(ets_event::kArray),
                                 [impl = impl_](uint8_t v) { impl->fireTestEventUINT8ArrayEvent({v, v, v}); });
    emission_.addTriggeredSource(std::string(ets_event::kReliable),
                                 [impl = impl_](uint8_t v) { impl->fireTestEventUINT8ReliableEvent(v); });
    emission_.addTriggeredSource(std::string(ets_event::kE2E),
                                 [impl = impl_](uint8_t v) { impl->fireTestEventUINT8E2EEvent(v); });
    emission_.addTriggeredSource(std::string(ets_event::kMulticast),
                                 [impl = impl_](uint8_t v) { impl->fireTestEventUINT8MulticastEvent(v); });
    // The extension's trigger policy, if it has one, replaces DefaultTriggerPolicy
    // now, before startEmission() starts the tick thread.
    emission_.installPolicy(extension.makeEmissionPolicy());

    // §5.1.6 SOMEIP_ETS_089 — bind suspendInterface override to a detached
    // unregister/re-register cycle. CommonAPI's unregisterService translates to
    // vsomeip stop_offer_service (wire: StopOfferService entry, ttl == 0);
    // registerService translates to offer_service (wire: OfferService entry,
    // ttl > 0). The closure captures shared_ptr copies of the runtime and stub
    // (never the ServerRole `this`), so the detached thread keeps them alive.
    impl_->setSuspendCallback(
        [runtime = runtime_, impl = impl_, lifecycle = std::move(lifecycle)](
            std::chrono::seconds start, std::chrono::seconds duration) {
            std::thread([runtime, impl, lifecycle, start, duration]() {
                if (start.count() > 0) {
                    std::this_thread::sleep_for(start);
                }
                runtime->unregisterService(ets_deploy::kDomain, ets_deploy::kInterface,
                                           ets_deploy::kInstance);
                // Post the StopOffer to dut_main's loop, which fires onSuspend on the
                // main-loop thread — before the down-period, so an activation-relative
                // emission can go quiet across the whole suspend window.
                if (lifecycle) {
                    lifecycle->post(LifecycleEvent::Suspend);
                }
                std::printf("tc8-dut: suspendInterface — service stopped for %lld s\n",
                            static_cast<long long>(duration.count()));
                std::this_thread::sleep_for(duration);
                if (!runtime->registerService(ets_deploy::kDomain, ets_deploy::kInstance, impl)) {
                    std::fprintf(stderr, "tc8-dut: suspendInterface re-register failed\n");
                } else {
                    // Post the warm re-offer, which fires onReactivate on the main-loop
                    // thread. Only on success — a failed re-register is not a re-activation.
                    if (lifecycle) {
                        lifecycle->post(LifecycleEvent::Reactivate);
                    }
                    std::printf("tc8-dut: suspendInterface — service resumed\n");
                }
            }).detach();
        });

    // §5.1.5.3 SD_MESSAGE_01/_02 + §5.1.5.7 RPC_14/_17 require two instances of
    // SERVICE-ID-1. Gated on TC8_DUT_INSTANCE_2 so the single-instance baseline
    // (every other §5.1.5 case) is unaffected. Each instance gets its own EtsImpl
    // so per-instance state (fieldA storage) doesn't leak between dispatchers.
    if (envFlagOn("TC8_DUT_INSTANCE_2")) {
        impl2_ = std::make_shared<EtsImpl>();
        if (!runtime_->registerService(ed::kDomain, ed::kInstance2, impl2_)) {
            std::fprintf(stderr, "tc8-dut: registerService(%s) failed\n", ed::kInstance2);
            std::_Exit(1);
        }
        std::printf("tc8-dut: %s registered (domain=%s instance=%s)\n", ed::kInterface,
                    ed::kDomain, ed::kInstance2);
        // A full instance of the same interface, so its fields carry initial events too.
        impl2_->seedFields(extension.testFieldUint8InitialValue());
    }

    // §5.1.5.7 RPC_01/_02/_13 require a second distinct service (SERVICE-ID-2 =
    // 0xF4E8). Gated on TC8_DUT_SERVICE_2 so the baseline single-service deployment
    // is unaffected. SERVICE-ID-2 gets its own cyclic TestEventUINT8 so RPC_02 has
    // a Notification to observe; it rides the single EmissionController (no separate
    // event thread) and is added before startEmission().
    if (envFlagOn("TC8_DUT_SERVICE_2")) {
        impl_si2_ = std::make_shared<Ets2Impl>();
        if (!runtime_->registerService(ed::kDomain, ed::kInstanceSi2, impl_si2_)) {
            std::fprintf(stderr, "tc8-dut: registerService(%s) failed\n", ed::kInstanceSi2);
            std::_Exit(1);
        }
        std::printf("tc8-dut: %s registered (domain=%s instance=%s)\n", ed::kInterfaceSi2,
                    ed::kDomain, ed::kInstanceSi2);
        emission_.addCyclicSource(
            "TestEventUINT8.SI2",
            [impl_si2 = impl_si2_](uint8_t v) { impl_si2->fireTestEventUINT8Event(v); },
            std::chrono::milliseconds(250));
    }
}

ServerRole::~ServerRole() = default;

IEtsFieldAccess& ServerRole::fieldAccess() { return *fields_; }

void ServerRole::startEmission() { emission_.start(); }

void ServerRole::stopEmission() { emission_.stop(); }

void ServerRole::unregisterAll() {
    namespace ed = ets_deploy;
    if (impl_si2_) {
        runtime_->unregisterService(ed::kDomain, ed::kInterfaceSi2, ed::kInstanceSi2);
    }
    if (impl2_) {
        runtime_->unregisterService(ed::kDomain, ed::kInterface, ed::kInstance2);
    }
    runtime_->unregisterService(ed::kDomain, ed::kInterface, ed::kInstance);
}

}  // namespace tc8::dut
