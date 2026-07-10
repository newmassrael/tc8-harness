#pragma once

#include <memory>
#include <thread>

#include <vsomeip/vsomeip.hpp>

namespace tc8::dut {

// Owns the DUT's SINGLE vsomeip::application in CLIENT-ONLY mode, created WITHOUT
// offering or finding any service. In client-only mode the DUT must NOT offer its
// ETS service (a local offer would make vsomeip satisfy the OEM client subscribe
// IN-PROCESS — local Ack, no wire SubscribeEventgroup — so the tester never sees
// it), yet the raw-vsomeip seams (event sink / client control / control channel)
// still need the application, which they retrieve by CommonAPI::DEFAULT_CONNECTION_ID
// (see acquireCommonApiApplication).
//
// The application is created DIRECTLY via vsomeip — create_application + init +
// a threaded start — NOT by building a CommonAPI proxy. A CommonAPI proxy's init()
// UNCONDITIONALLY request_service()s its target, which makes vsomeip's SD client
// emit a FindService at boot. Because that Find targets the SAME ClientTarget
// service the tester-driven Find does, it both pre-empts the tester-triggered Find
// AND (via vsomeip's per-service request_service dedup) suppresses it, leaving the
// Initial-Wait measurement window empty. A bare init()+start()ed application emits
// NO service-discovery traffic — SD entries derive solely from request_service /
// offer_service — so the FIRST FindService is now the one a control-driven
// IEtsClientControl::findService emits after the tester's activate, exactly where a
// conformant third-party client emits it.
//
// INVARIANT — sole creator of the default-connection application. The application is
// created under CommonAPI::DEFAULT_CONNECTION_ID (the empty connection id that keys
// vsomeip's application map; the display/config name still comes from
// VSOMEIP_APPLICATION_NAME, resolved in init()). vsomeip's create_application does
// NOT reuse an existing name — it MANGLES a collision to "<name>_N" — and CommonAPI's
// Connection constructor also calls create_application unconditionally (it never
// reuses). So constructing ANY CommonAPI proxy or stub on the default connection in
// client-only mode is FORBIDDEN: it would spin up a SECOND, "_N"-mangled routing
// client while the seams keep resolving this one via get_application("") — a silent
// split with no shared routing. This holds by design (the seams operate on the raw
// application and the OEM extension drives them, never CommonAPI), and start()
// fail-fasts if the application already exists when it runs. Unlike the prior
// proxy-vehicle, whose CommonAPI Factory cached and REUSED one Connection, this
// narrows app ownership to "this class only" — enforced at creation, contract-bound
// thereafter. (Server mode is different: there CommonAPI's registerService creates
// and owns the application, and this class is unused.)
class ClientOnlyApplication {
public:
    ClientOnlyApplication();
    ~ClientOnlyApplication();

    ClientOnlyApplication(const ClientOnlyApplication&) = delete;
    ClientOnlyApplication& operator=(const ClientOnlyApplication&) = delete;

    // Create the application under CommonAPI::DEFAULT_CONNECTION_ID, init it, and run
    // its event loop on a dedicated thread (application::start blocks). Offers and
    // finds nothing. Called ONCE from the main thread at boot — not concurrency-safe
    // (no lock); "idempotent" here means only that a redundant call on an
    // already-started instance is a no-op true. Returns false — TERMINAL, the caller
    // hard-exits and MUST NOT retry — if the default-connection application already
    // exists (invariant violation) or if create_application / init failed.
    bool start();

    // Best-effort teardown: stop the event loop and join the thread. The DUT
    // hard-exits via std::_Exit (dut_main.cpp), which SKIPS this — and deliberately,
    // because dropping the last reference to a started vsomeip application can block
    // in its shutdown handshake (the documented reason for _Exit). So this is NOT a
    // relied-upon graceful path; it exists so the object is self-consistent (RAII)
    // and safe to destroy on a path the DUT does not currently take.
    void stop();

private:
    std::shared_ptr<vsomeip::application> app_;
    std::thread                           thread_;
};

}  // namespace tc8::dut
