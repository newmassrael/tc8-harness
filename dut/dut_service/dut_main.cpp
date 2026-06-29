#include <atomic>
#include <chrono>
#include <csignal>
#include <cstdio>
#include <cstdlib>
#include <memory>
#include <thread>

#include <CommonAPI/CommonAPI.hpp>

#include "client_mode_proxy.h"
#include "ets2_impl.h"
#include "ets_client_control.h"
#include "ets_emission.h"
#include "ets_event_sink.h"
#include "ets_extension.h"
#include "ets_factory.h"
#include "ets_fault.h"
#include "ets_impl.h"
#include "posix_socket_backend.h"
#include "posix_stack_probe.h"
#include "posix_ut_extensions.h"
#include "tc8/dut_config.h"
#include "testability/protocol_server.h"
#include "upper_tester/ut_server.h"

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

// Bring up the CommonAPI-owned vsomeip application WITHOUT offering any service,
// for client-only mode. CommonAPI has no offer-free app-creation primitive —
// registerService and buildProxy are its only two app-creation triggers, both
// keyed on DEFAULT_CONNECTION_ID — so the seam factories (which retrieve
// get_application("")) resolve the app either way. We build a proxy purely as the
// app-creation vehicle: ClientModeProxyRunner is reused here ONLY for that side
// effect, NOT its ETS_097 role (subscribe() is never called), and the proxy's
// FindService for its target is harmless unrelated SD traffic. The returned
// runner OWNS the application and MUST be kept alive for the whole run.
std::unique_ptr<tc8::dut::ClientModeProxyRunner> bringUpClientOnlyApplication() {
    auto app = std::make_unique<tc8::dut::ClientModeProxyRunner>();
    if (!app->start()) {
        std::fprintf(stderr, "tc8-dut: client-only application bring-up failed\n");
        std::_Exit(1);
    }
    return app;
}

}  // namespace

int main() {
    std::setvbuf(stdout, nullptr, _IOLBF, 0);
    std::signal(SIGINT, onSignal);
    std::signal(SIGTERM, onSignal);

    auto runtime = CommonAPI::Runtime::get();

    // Client-role (CLT) topology: the DUT is a pure CLIENT of the primary ETS service
    // (0xF4E7), so in client-only mode it must NOT offer 0xF4E7 — a local offer
    // makes vsomeip satisfy the OEM client subscribe IN-PROCESS (local Ack, no
    // wire SubscribeEventgroup), so the tester (server) never sees it. The seam
    // factories still need the CommonAPI-owned vsomeip application (retrieved by
    // DEFAULT_CONNECTION_ID); building a proxy creates it WITHOUT offering any
    // service (see bringUpClientOnlyApplication). Server-role objects below — the
    // EtsImpl stub, emission engine, SI2/instance-2 offers, suspend callback — are
    // created/wired only when !client_only, so none is allocated in client-only.
    const bool client_only = envFlagOn("TC8_DUT_CLIENT_ONLY");
    std::shared_ptr<tc8::dut::EtsImpl> impl;  // server-role stub; unset in client-only
    std::unique_ptr<tc8::dut::ClientModeProxyRunner> client_only_app;
    if (client_only) {
        client_only_app = bringUpClientOnlyApplication();
        std::printf("tc8-dut: client-only mode — %s NOT offered; app created via proxy\n",
                    kInterface);
    } else {
        impl = tc8::dut::createEtsStub();
        if (!runtime->registerService(kDomain, kInstance, impl)) {
            std::fprintf(stderr, "tc8-dut: registerService failed\n");
            // Hard-exit — avoid static destructors running vsomeip shutdown
            // against a half-initialised routing manager, which hangs the process.
            std::_Exit(1);
        }
        std::printf("tc8-dut: %s registered (domain=%s instance=%s)\n",
                    kInterface, kDomain, kInstance);

        // §5.1.6 SOMEIP_ETS_121 — seed TestFieldUINT8 (notifier 0x8006) with a
        // non-default value so CommonAPI has a payload to send as the field's
        // initial Notification on each SubscribeEventgroupAck. Without a set value
        // vsomeip logs "Event payload not (yet) set" and skips the initial event,
        // so the Explicit Initial Data Control path stays unobservable. A non-zero
        // value is required because the setter only pushes to vsomeip when the value
        // changes from its default-constructed 0.
        impl->setTestFieldUINT8Attribute(static_cast<uint8_t>(0x42));
    }

    // OEM event sink (O2): the CommonAPI service's OWN vsomeip application, so the
    // extension shares one routing client (no second app). makeEtsEventSink
    // retrieves it by CommonAPI's default connection id — see its header. Declared
    // before the extension so it outlives it; the sink also unregisters its vsomeip
    // handlers on destruction, so a captured reference cannot dangle on a graceful
    // shutdown (today the DUT std::_Exit()s at the end of main, which skips both
    // dtors — see the exit comment below).
    std::unique_ptr<tc8::dut::IEtsEventSink> ets_sink =
        tc8::dut::makeEtsEventSink(tc8::dut::kServiceId, tc8::dut::kInstanceId);

    // OEM client control (O2, CLT topology): the same CommonAPI-owned vsomeip
    // application, used CLIENT-side so the extension can drive the DUT to
    // subscribe to / call a tester-offered service (no second app). Declared
    // before the extension so it outlives the EtsExtensionContext that hands it to
    // every hook; the extension's vsomeip-thread handlers capture it by reference.
    std::unique_ptr<tc8::dut::IEtsClientControl> ets_client =
        tc8::dut::makeEtsClientControl();

    // OEM extend seam (O2): no-op in the public DUT. An OEM TU (selected via
    // TC8_ETS_EXTENSION_SRC) offers its NDA event surface on the sink above and
    // may opt 0x8001 into trigger-driven emission. Created before the emission
    // engine because the 0x8001 source kind is chosen from ets8001TriggerDriven().
    std::unique_ptr<tc8::dut::IEtsExtension> ets_extension = tc8::dut::createEtsExtension();

    // Single emission engine (one producer per event). 0x8001/TestEventUINT8 is
    // CYCLIC by default — the DUT's pre-existing unconditional 250 ms cadence the
    // §5.1.5 suite relies on — unless the OEM extension opts it into a TRIGGERED
    // source (armed by triggerEventUINT8), letting its must-NOT-send-0x8001 cases
    // hold. The four new events are always TRIGGERED — they fire only after their
    // triggerEventX Method, so must-NOT-send cases hold. start() is deferred until
    // after the optional SI2 source is added; stop() runs before _Exit (which
    // skips dtors). The per-source payload counter is owned by the controller and
    // passed into each closure (no hidden statics).
    // Server-role event emission: fires Notifications through the (registered)
    // stub, so it is set up only when the DUT offers the service. In client-only
    // mode the stub is never registered (its CommonAPI adapter is unbound), so
    // firing would be invalid — skip the whole engine.
    tc8::dut::EmissionController emission;
    if (!client_only) {
        impl->setEmissionController(&emission);
        auto fireBasic = [impl](uint8_t v) { impl->fireTestEventUINT8Event(v); };
        if (ets_extension->ets8001TriggerDriven()) {
            emission.addTriggeredSource(std::string(tc8::dut::ets_event::kBasic), fireBasic);
        } else {
            emission.addCyclicSource(std::string(tc8::dut::ets_event::kBasic), fireBasic,
                                     std::chrono::milliseconds(250));
        }
        emission.addTriggeredSource(std::string(tc8::dut::ets_event::kArray),
                                    [impl](uint8_t v) { impl->fireTestEventUINT8ArrayEvent({v, v, v}); });
        emission.addTriggeredSource(std::string(tc8::dut::ets_event::kReliable),
                                    [impl](uint8_t v) { impl->fireTestEventUINT8ReliableEvent(v); });
        emission.addTriggeredSource(std::string(tc8::dut::ets_event::kE2E),
                                    [impl](uint8_t v) { impl->fireTestEventUINT8E2EEvent(v); });
        emission.addTriggeredSource(std::string(tc8::dut::ets_event::kMulticast),
                                    [impl](uint8_t v) { impl->fireTestEventUINT8MulticastEvent(v); });
    }

    // The server sink + client control handed to every extension hook as one
    // context (owned here for the whole run). Now that the service is offered, let
    // the OEM extension (O2) offer its NDA event surface and wire any client
    // subscribe/calls. No-op for the public default extension (its
    // ets8001TriggerDriven() already chose the 0x8001 source kind above).
    tc8::dut::EtsExtensionContext ets_ctx{*ets_sink, *ets_client};
    ets_extension->onRegister(ets_ctx);

    // §5.1.6 SOMEIP_ETS_089 — bind suspendInterface override to a
    // detached unregister/re-register cycle. CommonAPI's
    // unregisterService translates to vsomeip stop_offer_service (wire:
    // StopOfferService entry with ttl == 0); registerService translates
    // to offer_service (wire: OfferService entry with ttl > 0).
    if (!client_only) {
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
    }

    // §5.1.5.3 SD_MESSAGE_01/_02 + §5.1.5.7 RPC_14/_17 require two
    // instances of SERVICE-ID-1. Gated on TC8_DUT_INSTANCE_2 so the
    // single-instance baseline (every other §5.1.5 case) is unaffected.
    // Each instance gets its own EtsImpl so per-instance state
    // (fieldA storage) doesn't leak between dispatchers.
    std::shared_ptr<tc8::dut::EtsImpl> impl2;
    if (!client_only && envFlagOn("TC8_DUT_INSTANCE_2")) {
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
    std::shared_ptr<tc8::dut::Ets2Impl> impl_si2;
    if (!client_only && envFlagOn("TC8_DUT_SERVICE_2")) {
        impl_si2 = std::make_shared<tc8::dut::Ets2Impl>();
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
    // UT lives on 20000 (data) + 30600 (RPC). The UT and testability endpoints
    // below are the role-INDEPENDENT control plane (they drive the DUT, not the
    // SOME/IP server surface), so they run in client-only mode too — deliberately
    // NOT gated on !client_only, unlike the server-role offer/emission/SI2/suspend.
    // The §4.5 and §4.7 autoconf + DHCP opcode families and the interface
    // enumeration are POSIX-host-specific, so they live in PosixUtExtensions and
    // register onto the platform-agnostic core. `ut_ext` is declared first so it
    // outlives `upper_tester` — the registered handlers capture its members.
    tc8::dut::PosixUtExtensions ut_ext;
    ut_ext.discoverInterfaces();
    tc8::ut::UpperTesterServer upper_tester{std::make_unique<tc8::dut::PosixSocketBackend>(),
                                            std::make_unique<tc8::dut::PosixStackProbe>()};
    ut_ext.registerOn(upper_tester);
    // §5.1.6 ETS_103/104/105/146/166/167/168 + §5.1.5 SOMEIPSRV_RPC_11 EtsImpl fault arm (UT 0x1B
    // OpSetEtsFlavor). tc8-dut-only:
    // the SOME/IP EtsImpl is harness-owned, so this is the only faithful SOME/IP fault site
    // (the wire serialization is vendored-vsomeip). The lwIP fixture carries no SOME/IP service
    // and never registers it, so the matching `_neg` capability-skips there.
    upper_tester.registerOpcode(
        tc8::ut::OpSetEtsFlavor,
        [](const std::uint8_t *params, std::size_t len, std::uint8_t &status,
           std::vector<std::uint8_t> & /*body*/) {
            if (len < 1 || params[0] > tc8::ut::kEtsFaultMax) {
                status = tc8::ut::kStatusMalformed;
                return;
            }
            tc8::dut::setEtsFaultFlavor(params[0]);
            status = tc8::ut::kStatusOk;
        });
    if (!upper_tester.start(ut_ext.ifaceIpBe(), ut_ext.ifaceBcastBe())) {
        std::fprintf(stderr, "tc8-dut: upper-tester start failed\n");
        std::_Exit(1);
    }

    // AUTOSAR Testability Protocol endpoint (PRS Testability TC 1.2.0). The
    // standard-protocol UT channel, additive to the opcode UT above: a
    // standard-compliant tester drives the DUT over SOME/IP on the testability
    // port (30700). A bind failure is non-fatal — the opcode UT still serves
    // the in-tree cases; testability is an OEM-neutral enablement channel.
    tc8::testability::ProtocolServer testability{std::make_unique<tc8::dut::PosixSocketBackend>()};
    if (!testability.start()) {
        std::fprintf(stderr, "tc8-dut: testability endpoint start failed (continuing)\n");
    }

    // §5.1.5.5 BASIC_03 + §5.1.5.4 SD_MESSAGE event-flow cases require the DUT to
    // emit Notifications post-Subscribe. CommonAPI's stub queues a notification;
    // vsomeip distributes it only to currently subscribed clients, so the cyclic
    // TestEventUINT8 is harmless when no one listens, and its 250 ms cadence keeps
    // post-Subscribe latency under the SCXML observation deadline. SERVICE-ID-2
    // (impl_si2, when registered) gets its own cyclic TestEventUINT8 so RPC_02 has
    // a Notification to observe. Both ride the single EmissionController — there
    // is no separate event thread.
    if (!client_only) {
        if (impl_si2) {
            emission.addCyclicSource("TestEventUINT8.SI2",
                                     [impl_si2](uint8_t v) { impl_si2->fireTestEventUINT8Event(v); },
                                     std::chrono::milliseconds(250));
        }
        emission.start();
    }

    while (!g_stop.load()) {
        ets_extension->onTick(ets_ctx);
        std::this_thread::sleep_for(std::chrono::milliseconds(200));
    }

    if (!client_only) {
        emission.stop();
    }
    ets_extension->onStop(ets_ctx);
    testability.stop();
    upper_tester.stop();
    if (impl_si2) {
        runtime->unregisterService(kDomain, kInterfaceSi2, kInstanceSi2);
    }
    if (impl2) {
        runtime->unregisterService(kDomain, kInterface, kInstance2);
    }
    // The primary service is unregistered only if it was offered — client-only
    // mode never registered it (a no-op unregister just logs a CommonAPI warning).
    if (!client_only) {
        runtime->unregisterService(kDomain, kInterface, kInstance);
    }
    std::printf("tc8-dut: unregistered, exiting\n");
    // Hard-exit: vsomeip application destructor blocks during static dtor
    // chain (routing manager shutdown handshake against itself). _Exit
    // skips dtors and releases the process cleanly.
    std::_Exit(0);
}
