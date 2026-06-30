#include <atomic>
#include <chrono>
#include <csignal>
#include <cstdio>
#include <cstdlib>
#include <memory>
#include <optional>
#include <thread>

#include <CommonAPI/CommonAPI.hpp>

#include "client_mode_proxy.h"
#include "env_flag.h"
#include "ets_client_control.h"
#include "ets_control_channel.h"
#include "ets_event_sink.h"
#include "ets_extension.h"
#include "ets_fault.h"
#include "ets_io_host.h"
#include "pollable_host.h"
#include "posix_socket_backend.h"
#include "posix_stack_probe.h"
#include "posix_ut_extensions.h"
#include "server_role.h"
#include "tc8/dut_config.h"
#include "testability/protocol_server.h"
#include "upper_tester/ut_server.h"

namespace {

std::atomic<bool> g_stop{false};

void onSignal(int /*signum*/) { g_stop.store(true); }

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

    // OEM extend seam (O2): no-op in the public DUT. An OEM TU (selected via
    // TC8_ETS_EXTENSION_SRC) offers its NDA event surface on the sink below and may
    // opt 0x8001 into trigger-driven emission. Created first because the server
    // role queries ets8001TriggerDriven() while wiring its 0x8001 source; the query
    // happens once, in the ServerRole constructor. createEtsExtension has no
    // dependencies, so constructing it here — before the application exists — is
    // well-defined.
    std::unique_ptr<tc8::dut::IEtsExtension> ets_extension = tc8::dut::createEtsExtension();

    // Client-role (CLT) topology vs server role. In client-only mode the DUT is a
    // pure CLIENT of the primary ETS service (0xF4E7) and must NOT offer it: a
    // local offer makes vsomeip satisfy the OEM client subscribe IN-PROCESS (local
    // Ack, no wire SubscribeEventgroup), so the tester (server) never sees it. The
    // seam factories below still need the CommonAPI-owned vsomeip application
    // (retrieved by DEFAULT_CONNECTION_ID); building a proxy creates it WITHOUT
    // offering any service (bringUpClientOnlyApplication). Otherwise the DUT takes
    // the SERVER role: a ServerRole registers the service(s), wires emission, and
    // owns the suspendInterface re-offer — none of which exists in client-only
    // mode. Constructing the ServerRole before the seam factories is REQUIRED:
    // registerService is what synchronously creates the application they retrieve.
    const bool client_only = tc8::dut::envFlagOn("TC8_DUT_CLIENT_ONLY");
    std::unique_ptr<tc8::dut::ClientModeProxyRunner> client_only_app;
    std::optional<tc8::dut::ServerRole> server;
    if (client_only) {
        client_only_app = bringUpClientOnlyApplication();
        std::printf("tc8-dut: client-only mode — %s NOT offered; app created via proxy\n",
                    tc8::dut::ets_deploy::kInterface);
    } else {
        server.emplace(runtime, *ets_extension);
    }

    // OEM event sink (O2): the CommonAPI service's OWN vsomeip application, so the
    // extension shares one routing client (no second app). makeEtsEventSink
    // retrieves it by CommonAPI's default connection id — see its header. Declared
    // before the extension context so it outlives it; the sink also unregisters its
    // vsomeip handlers on destruction, so a captured reference cannot dangle on a
    // graceful shutdown (today the DUT std::_Exit()s at the end of main, which skips
    // both dtors — see the exit comment below).
    std::unique_ptr<tc8::dut::IEtsEventSink> ets_sink =
        tc8::dut::makeEtsEventSink(tc8::dut::kServiceId, tc8::dut::kInstanceId);

    // OEM client control (O2, CLT topology): the same CommonAPI-owned vsomeip
    // application, used CLIENT-side so the extension can drive the DUT to subscribe
    // to / call a tester-offered service (no second app). Declared before the
    // extension context so it outlives the EtsExtensionContext that hands it to
    // every hook; the extension's vsomeip-thread handlers capture it by reference.
    std::unique_ptr<tc8::dut::IEtsClientControl> ets_client =
        tc8::dut::makeEtsClientControl();

    // OEM inbound control channel (O2, CLT topology): offers a control service the
    // tester drives a client-only DUT through (no second app — same CommonAPI-owned
    // application as the sink/client). Declared before the extension context so it
    // outlives the EtsExtensionContext that hands it to every hook.
    std::unique_ptr<tc8::dut::IEtsControlChannel> ets_control =
        tc8::dut::makeEtsControlChannel();

    // Runtime-I/O host: an extension that needs raw receive (e.g. a UDP receiver on
    // ports vsomeip does not own) adopts a pollable here, and the main loop below
    // drains it. Owned here so it outlives the EtsExtensionContext, like the facades
    // above. The public default extension adopts nothing — the host stays empty and
    // the loop keeps its prior sleep cadence.
    tc8::dut::PollableHost ets_io;

    // The server sink + client control + control channel + I/O host handed to every
    // extension hook as one context (owned here for the whole run). Now that the
    // service is offered (in server mode) and the application exists (both modes),
    // let the OEM extension (O2) offer its NDA event surface and wire any client
    // subscribe/calls. No-op for the public default extension (its
    // ets8001TriggerDriven() already chose the 0x8001 source kind in the ServerRole
    // constructor above).
    tc8::dut::EtsExtensionContext ets_ctx{*ets_sink, *ets_client, *ets_control, ets_io};
    ets_extension->onRegister(ets_ctx);

    // TC8 §4.8.5 Upper Tester channel. UDP-bound listeners for
    // ADDRESSING_01/02 receive-probing and FRAGMENTS_05 send-triggering.
    // Independent of the SOME/IP stack — vsomeip owns 30490..30510,
    // UT lives on 20000 (data) + 30600 (RPC). The UT and testability endpoints
    // below are the role-INDEPENDENT control plane (they drive the DUT, not the
    // SOME/IP server surface), so they run in client-only mode too — deliberately
    // NOT gated on the server role, unlike the offer/emission/SI2/suspend the
    // ServerRole owns. The §4.5 and §4.7 autoconf + DHCP opcode families and the
    // interface enumeration are POSIX-host-specific, so they live in
    // PosixUtExtensions and register onto the platform-agnostic core. `ut_ext` is
    // declared first so it outlives `upper_tester` — the registered handlers
    // capture its members.
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
    // emit Notifications post-Subscribe. The cyclic TestEventUINT8 is harmless when
    // no one listens, and its 250 ms cadence keeps post-Subscribe latency under the
    // SCXML observation deadline. Started here — after the seam + UT + testability
    // bring-up — at the same point the pre-extraction dut_main called
    // emission.start(), so the cadence's first fire is unchanged. Client-only mode
    // has no ServerRole and therefore no cadence to start.
    if (server) {
        server->startEmission();
    }

    // onTick fires on a steady ~200 ms cadence (the OEM extension's cyclic /
    // duration-windowed hook); between ticks the loop drains any pollable receiver
    // the extension adopted, waking immediately on incoming data instead of sleeping
    // blind. With no adopted receiver, drainReady is a 200 ms sleep — so the onTick
    // cadence matches the prior sleep loop whenever onTick completes within the
    // window (an onTick that overran 200 ms would tick back-to-back, exactly as it
    // would have under the old loop's post-onTick sleep).
    auto next_tick = std::chrono::steady_clock::now();
    while (!g_stop.load()) {
        const auto now = std::chrono::steady_clock::now();
        if (now >= next_tick) {
            ets_extension->onTick(ets_ctx);
            next_tick = std::chrono::steady_clock::now() + std::chrono::milliseconds(200);
        }
        const auto remaining =
            std::chrono::duration_cast<std::chrono::milliseconds>(next_tick - now).count();
        ets_io.drainReady(remaining > 0 ? static_cast<int>(remaining) : 0);
    }

    if (server) {
        server->stopEmission();
    }
    ets_extension->onStop(ets_ctx);
    testability.stop();
    upper_tester.stop();
    // StopOfferService for every offered instance/service — only in the server
    // role (client-only never offered anything).
    if (server) {
        server->unregisterAll();
    }
    std::printf("tc8-dut: unregistered, exiting\n");
    // Hard-exit: vsomeip application destructor blocks during static dtor
    // chain (routing manager shutdown handshake against itself). _Exit
    // skips dtors and releases the process cleanly.
    std::_Exit(0);
}
