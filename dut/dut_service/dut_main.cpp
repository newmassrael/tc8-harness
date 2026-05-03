#include <atomic>
#include <chrono>
#include <csignal>
#include <cstdio>
#include <cstdlib>
#include <memory>
#include <thread>

#include <CommonAPI/CommonAPI.hpp>

#include "ets_impl.h"
#include "ets_impl_2.h"
#include "upper_tester_server.h"

namespace {

std::atomic<bool> g_stop{false};

void onSignal(int /*signum*/) { g_stop.store(true); }

constexpr const char* kDomain    = "local";
constexpr const char* kInstance  = "ETS";
constexpr const char* kInstance2 = "ETS2";
constexpr const char* kInterface = "org.tc8.ets.EnhancedTestability:v1_0";

// SERVICE-ID-2 (multi-service axis) — separate fdepl with its own
// SomeIpServiceID (0xF4E8). Lives on the same domain as ETS but routes
// to a distinct stub implementation.
constexpr const char* kInstanceSi2  = "ETS_SI2";
constexpr const char* kInterfaceSi2 = "org.tc8.ets2.EnhancedTestability2:v1_0";

bool envFlagOn(const char* name) {
    const char* v = std::getenv(name);
    return v != nullptr && v[0] != '\0' && v[0] != '0';
}

}  // namespace

int main() {
    std::setvbuf(stdout, nullptr, _IOLBF, 0);
    std::signal(SIGINT, onSignal);
    std::signal(SIGTERM, onSignal);

    auto runtime = CommonAPI::Runtime::get();
    auto impl = std::make_shared<tc8::dut::EtsImpl>();

    if (!runtime->registerService(kDomain, kInstance, impl)) {
        std::fprintf(stderr, "tc8-dut: registerService failed\n");
        // Hard-exit — avoid static destructors running vsomeip shutdown
        // against a half-initialised routing manager, which hangs the process.
        std::_Exit(1);
    }
    std::printf("tc8-dut: %s registered (domain=%s instance=%s)\n",
                kInterface, kDomain, kInstance);

    // §5.1.6 SOMEIP_ETS_089 — bind suspendInterface override to a
    // detached unregister/re-register cycle. CommonAPI's
    // unregisterService translates to vsomeip stop_offer_service (wire:
    // StopOfferService entry with ttl == 0); registerService translates
    // to offer_service (wire: OfferService entry with ttl > 0).
    impl->setSuspendCallback([runtime, impl](uint32_t start_ms, uint32_t duration_ms) {
        std::thread([runtime, impl, start_ms, duration_ms]() {
            if (start_ms > 0) {
                std::this_thread::sleep_for(std::chrono::milliseconds(start_ms));
            }
            runtime->unregisterService(kDomain, kInterface, kInstance);
            std::printf("tc8-dut: suspendInterface — service stopped for %u ms\n", duration_ms);
            std::this_thread::sleep_for(std::chrono::milliseconds(duration_ms));
            if (!runtime->registerService(kDomain, kInstance, impl)) {
                std::fprintf(stderr, "tc8-dut: suspendInterface re-register failed\n");
            } else {
                std::printf("tc8-dut: suspendInterface — service resumed\n");
            }
        }).detach();
    });

    // §5.1.5.3 SD_MESSAGE_01/_02 + §5.1.5.7 RPC_14/_17 require two
    // instances of SERVICE-ID-1. Gated on TC8_DUT_INSTANCE_2 so the
    // single-instance baseline (every other §5.1.5 case) is unaffected.
    // Each instance gets its own EtsImpl so per-instance state
    // (fieldA storage) doesn't leak between dispatchers.
    std::shared_ptr<tc8::dut::EtsImpl> impl2;
    if (envFlagOn("TC8_DUT_INSTANCE_2")) {
        impl2 = std::make_shared<tc8::dut::EtsImpl>();
        if (!runtime->registerService(kDomain, kInstance2, impl2)) {
            std::fprintf(stderr, "tc8-dut: registerService(%s) failed\n", kInstance2);
            std::_Exit(1);
        }
        std::printf("tc8-dut: %s registered (domain=%s instance=%s)\n",
                    kInterface, kDomain, kInstance2);
    }

    // §5.1.5.7 RPC_01/_02/_13 require a second distinct service
    // (SERVICE-ID-2 = 0xF4E8). Gated on TC8_DUT_SERVICE_2 so the
    // baseline single-service deployment is unaffected.
    std::shared_ptr<tc8::dut::EtsImpl2> impl_si2;
    if (envFlagOn("TC8_DUT_SERVICE_2")) {
        impl_si2 = std::make_shared<tc8::dut::EtsImpl2>();
        if (!runtime->registerService(kDomain, kInstanceSi2, impl_si2)) {
            std::fprintf(stderr, "tc8-dut: registerService(%s) failed\n", kInstanceSi2);
            std::_Exit(1);
        }
        std::printf("tc8-dut: %s registered (domain=%s instance=%s)\n",
                    kInterfaceSi2, kDomain, kInstanceSi2);
    }

    // TC8 §4.8.5 Upper Tester channel. UDP-bound listeners for
    // ADDRESSING_01/02 receive-probing and FRAGMENTS_05 send-triggering.
    // Independent of the SOME/IP stack — vsomeip owns 30490..30510,
    // UT lives on 20000 (data) + 30600 (RPC).
    tc8::dut::UpperTesterServer upper_tester;
    if (!upper_tester.start()) {
        std::fprintf(stderr, "tc8-dut: upper-tester start failed\n");
        std::_Exit(1);
    }

    // §5.1.5.5 BASIC_03 + §5.1.5.4 SD_MESSAGE event-flow cases require
    // the DUT to emit Notifications post-Subscribe. CommonAPI's stub
    // queues a notification; vsomeip distributes it only to currently
    // subscribed clients, so cyclic firing is harmless when no one
    // listens. 250 ms cadence keeps the post-Subscribe latency under
    // the SCXML observation deadline without flooding the wire.
    // SERVICE-ID-2 (impl_si2, when registered) gets a parallel cyclic
    // event so RPC_02 has a Notification to observe.
    std::thread event_thread([&impl, &impl_si2]() {
        uint8_t value = 0;
        while (!g_stop.load()) {
            impl->fireTestEventUINT8Event(value);
            if (impl_si2) {
                impl_si2->fireTestEventUINT8Event(value);
            }
            ++value;
            std::this_thread::sleep_for(std::chrono::milliseconds(250));
        }
    });

    while (!g_stop.load()) {
        std::this_thread::sleep_for(std::chrono::milliseconds(200));
    }

    if (event_thread.joinable()) {
        event_thread.join();
    }
    upper_tester.stop();
    if (impl_si2) {
        runtime->unregisterService(kDomain, kInterfaceSi2, kInstanceSi2);
    }
    if (impl2) {
        runtime->unregisterService(kDomain, kInterface, kInstance2);
    }
    runtime->unregisterService(kDomain, kInterface, kInstance);
    std::printf("tc8-dut: unregistered, exiting\n");
    // Hard-exit: vsomeip application destructor blocks during static dtor
    // chain (routing manager shutdown handshake against itself). _Exit
    // skips dtors and releases the process cleanly.
    std::_Exit(0);
}
